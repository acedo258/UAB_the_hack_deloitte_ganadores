"""Backend de la consola.  Responsable: C (consola).

    uvicorn api.server:app --port 8100 --reload

La API simulada de Deloitte va en el puerto 8000 y solo la usamos para aprobaciones y contención.
"""
from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from typing import Literal, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agent.triage import triage_alert
from core.config import CACHE_DIR, MOCK_API_URL, ROOT
from core.fingerprint import compute_patterns
from core.schemas import Ticket
from core.store import rows
from core.tools import PREFIX_SOURCE

app = FastAPI(title="SOC N1 · Tarvia", version="0.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TICKETS = CACHE_DIR / "tickets"
DECISIONS = ROOT / "data" / "decisions.jsonl"
_patterns: list[dict] | None = None
_alert_pattern: dict[str, dict] = {}


def patterns() -> list[dict]:
    global _patterns
    if _patterns is None:
        _patterns = compute_patterns()
        for p in _patterns:
            for aid in p["alert_ids"]:
                _alert_pattern[aid] = p
    return _patterns


def load_ticket(alert_id: str) -> Optional[Ticket]:
    for suffix in (".deep.json", ".json"):
        f = TICKETS / f"{alert_id}{suffix}"
        if f.exists():
            return Ticket.model_validate_json(f.read_text(encoding="utf-8"))
    return None


def save_ticket(t: Ticket) -> None:
    TICKETS.mkdir(parents=True, exist_ok=True)
    (TICKETS / f"{t.alert_ids[0]}.json").write_text(t.model_dump_json(indent=2), encoding="utf-8")


# ------------------------------------------------------------------ lectura
@app.get("/api/stats")
def stats():
    pats = patterns()
    n = rows("SELECT count(*) n FROM alerts")[0]["n"]
    triaged = len(list(TICKETS.glob("*.json"))) if TICKETS.exists() else 0
    return {"alerts": n, "patterns": len(pats), "outliers": sum(p["is_outlier"] for p in pats),
            "noise_patterns": sum(p["is_noise_candidate"] for p in pats), "triaged": triaged}


@app.get("/api/queue")
def queue_(dev: bool = True, rule_id: str = "", outliers_only: bool = False, limit: int = 100, offset: int = 0):
    patterns()
    cond, params = ["1=1"], []
    if dev:
        cond.append("dev_sample")
    if rule_id:
        cond.append("rule_id = ?"); params.append(rule_id)
    items = rows(f"SELECT alert_id, created_at, source_product, rule_id, rule_name, severity FROM alerts "
                 f"WHERE {' AND '.join(cond)} ORDER BY created_at", params)
    out = []
    for it in items:
        p = _alert_pattern.get(it["alert_id"], {})
        if outliers_only and not p.get("is_outlier"):
            continue
        t = load_ticket(it["alert_id"])
        out.append({**it, "pattern_id": p.get("pattern_id"), "pattern_count": p.get("count"), "is_outlier": p.get("is_outlier", False),
                    "ticket": None if t is None else {"verdict": t.verdict, "severity": t.severity, "confidence": t.confidence,
                                                      "title": t.title, "status": t.status, "escalate": t.escalation.escalate,
                                                      "manipulation_attempt": t.manipulation_attempt}})
    return {"total": len(out), "items": out[offset: offset + limit]}


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: str):
    r = rows("SELECT raw FROM alerts WHERE alert_id = ?", [alert_id])
    if not r:
        raise HTTPException(404)
    return {**r[0]["raw"], "pattern": {k: v for k, v in _alert_pattern.get(alert_id, {}).items() if k != "alert_ids"}}


@app.get("/api/events/{event_id}")
def event(event_id: str):
    src = PREFIX_SOURCE.get(event_id.split("-")[0])
    if not src:
        raise HTTPException(404, "prefijo de evento desconocido")
    r = rows(f"SELECT to_json(t) AS raw FROM {src} t WHERE event_id = ?", [event_id])
    if not r:
        raise HTTPException(404)
    return {"source": src, **r[0]["raw"]}


@app.get("/api/patterns")
def list_patterns(min_count: int = 1):
    return [{k: v for k, v in p.items() if k != "alert_ids"} | {"ticket": _ticket_brief(p["sample_alert_id"])}
            for p in patterns() if p["count"] >= min_count]


def _ticket_brief(aid: str):
    t = load_ticket(aid)
    return None if t is None else {"verdict": t.verdict, "severity": t.severity, "title": t.title, "status": t.status}


@app.get("/api/tickets/{alert_id}")
def ticket(alert_id: str):
    t = load_ticket(alert_id)
    if t is None:
        raise HTTPException(404, "sin triar")
    return t


# ------------------------------------------------------------------ triaje en directo (SSE)
@app.get("/api/triage/{alert_id}/stream")
def triage_stream(alert_id: str, deep: bool = False, force: bool = False):
    """Emite cada TraceStep como evento 'step' y al final el ticket como evento 'ticket'."""
    q: queue.Queue = queue.Queue()

    def work():
        try:
            t = triage_alert(alert_id, deep=deep, use_cache=not force, on_step=lambda s: q.put(("step", s.model_dump())))
            q.put(("ticket", t.model_dump()))
        except Exception as e:  # noqa: BLE001
            q.put(("error", {"detail": str(e)}))
        q.put(None)

    threading.Thread(target=work, daemon=True).start()

    def gen():
        while (item := q.get()) is not None:
            kind, data = item
            yield f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


# ------------------------------------------------------------------ decisiones humanas
class Decision(BaseModel):
    alert_id: str
    decision: Literal["approve", "correct", "escalate"]
    analyst: str = "analista"
    verdict: Optional[str] = None
    severity: Optional[str] = None
    comment: str = ""
    apply_to_pattern: bool = False      # aprobar el patrón entero con una sola decisión


@app.post("/api/decisions")
def decide(d: Decision):
    t = load_ticket(d.alert_id)
    if t is None:
        raise HTTPException(404, "triar antes de decidir")
    t.status = {"approve": "approved", "correct": "corrected", "escalate": "escalated"}[d.decision]
    if d.verdict:
        t.verdict = d.verdict  # type: ignore[assignment]
    if d.severity:
        t.severity = d.severity  # type: ignore[assignment]
    covered = [d.alert_id]
    if d.apply_to_pattern and (p := _alert_pattern.get(d.alert_id)):
        covered = p["alert_ids"]
    rec = {"ts": datetime.now(timezone.utc).isoformat(), **d.model_dump(), "alerts_covered": len(covered),
           "ai_verdict": t.verdict, "ai_severity": t.severity}
    DECISIONS.parent.mkdir(parents=True, exist_ok=True)
    with open(DECISIONS, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    save_ticket(t)
    return rec


# ------------------------------------------------------------------ contención (API simulada, con aprobación humana)
class Containment(BaseModel):
    ticket_id: str
    action: str
    target: str
    justification: str
    approver: str = ""           # nombre de la persona que aprueba en la consola


NO_APPROVAL = {"block_ioc", "purge_email"}


@app.post("/api/containment")
def contain(c: Containment):
    try:
        with httpx.Client(base_url=MOCK_API_URL, timeout=10) as h:
            token = ""
            if c.action not in NO_APPROVAL:
                if not c.approver:
                    raise HTTPException(400, "esta acción necesita una persona que la apruebe")
                ap = h.post("/approvals", json={"action": c.action, "target": c.target, "approver": c.approver, "reason": c.justification})
                ap.raise_for_status()
                token = ap.json()["approval_token"]
            r = h.post(f"/containment/{c.action}", json={"target": c.target, "justification": c.justification,
                                                         "approval_token": token, "ticket_id": c.ticket_id})
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.json().get("detail", r.text))
            return r.json()
    except httpx.ConnectError:
        raise HTTPException(503, f"API simulada no disponible en {MOCK_API_URL} (arráncala: uvicorn mock_soc_api:app --port 8000)")


@app.get("/api/containment/log")
def containment_log():
    try:
        return httpx.get(f"{MOCK_API_URL}/containment/log", timeout=5).json()
    except httpx.HTTPError:
        return []
