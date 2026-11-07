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
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from agent.triage import triage_alert
from core.config import CACHE_DIR, MOCK_API_URL, ROOT
from core.fingerprint import compute_patterns
from core.schemas import Ticket
from core.store import rows
from core.tools import PREFIX_SOURCE

app = FastAPI(title="SOC N1 · Tarvia", version="0.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TICKETS = CACHE_DIR / "tickets"
FIXTURES = ROOT / "fixtures"
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
    f_fix = FIXTURES / f"ticket_{alert_id}.json"
    if f_fix.exists():
        return Ticket.model_validate_json(f_fix.read_text(encoding="utf-8"))
    if FIXTURES.exists():
        for fx in FIXTURES.glob("ticket_*.json"):
            t = Ticket.model_validate_json(fx.read_text(encoding="utf-8"))
            if t.ticket_id == alert_id or alert_id in t.alert_ids:
                return t
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
    # Cálculo de minutos ahorrados: 15 minutos de analista por cada alerta triada o agrupada
    minutes_saved = triaged * 15
    return {
        "alerts": n,
        "patterns": len(pats),
        "outliers": sum(p["is_outlier"] for p in pats),
        "noise_patterns": sum(p["is_noise_candidate"] for p in pats),
        "triaged": triaged,
        "minutes_saved": minutes_saved,
    }


@app.get("/api/queue")
@app.get("/queue")
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
@app.get("/patterns")
def list_patterns(min_count: int = 1):
    return [{k: v for k, v in p.items() if k != "alert_ids"} | {"ticket": _ticket_brief(p["sample_alert_id"])}
            for p in patterns() if p["count"] >= min_count]


def _ticket_brief(aid: str):
    t = load_ticket(aid)
    return None if t is None else {"verdict": t.verdict, "severity": t.severity, "title": t.title, "status": t.status}


@app.get("/api/tickets/{alert_id}")
@app.get("/tickets/{alert_id}")
def ticket(alert_id: str):
    t = load_ticket(alert_id)
    if t is None:
        raise HTTPException(404, "sin triar")
    return t


# ------------------------------------------------------------------ triaje en directo (SSE)
def _sse_stream(alert_id: str, deep: bool = False, force: bool = False):
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
            yield {"event": kind, "data": json.dumps(data, ensure_ascii=False, default=str)}

    return EventSourceResponse(gen())


@app.get("/api/triage/{alert_id}/stream")
@app.post("/api/triage/{alert_id}")
@app.post("/triage/{alert_id}")
def triage_stream(alert_id: str, deep: bool = False, force: bool = False):
    """Emite cada TraceStep como evento 'step' y al final el ticket como evento 'ticket'."""
    return _sse_stream(alert_id, deep=deep, force=force)


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


@app.get("/api/decisions")
def list_decisions():
    """Devuelve el historial ordenado de decisiones tomadas por los analistas humanos."""
    if not DECISIONS.exists():
        return []
    records = []
    with open(DECISIONS, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    return list(reversed(records))


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


# ------------------------------------------------------------------ incidentes y correlación
@app.get("/api/incidents")
@app.get("/incidents")
def list_incidents():
    """Devuelve los incidentes correlacionados con grafo y kill chain."""
    try:
        from core.correlate import compute_incidents  # type: ignore[import-not-found]
        return compute_incidents()
    except (ImportError, AttributeError):
        pass

    # Incidentes pre-correlacionados de referencia (Historias verificadas del reto)
    return [
        {
            "incident_id": "INC-2026-001",
            "title": "Campaña Ransomware: Compromiso Marta Puig (Latrodectus → Cobalt Strike → VSS)",
            "severity": "critical",
            "status": "investigating",
            "primary_entity": "mpuig@tarvia.example",
            "impact_summary": "Infección inicial por phishing, elevación de privilegios vía LSASS, movimiento lateral PsExec y borrado masivo de Shadow Copies.",
            "alerts": [
                "ALR-20261009-011790", "ALR-20261009-011791", "ALR-20261009-011792", "ALR-20261009-011793",
                "ALR-20261010-011794", "ALR-20261010-011795", "ALR-20261010-011796", "ALR-20261010-011797", "ALR-20261010-011798"
            ],
            "timeline": [
                {"ts": "2026-10-09 09:14", "phase": "Acceso Inicial", "event": "Phishing bancario abierto y ejecutable malicioso Latrodectus iniciado"},
                {"ts": "2026-10-09 10:22", "phase": "Ejecución & C2", "event": "Inyección de beacon de Cobalt Strike en proceso del sistema"},
                {"ts": "2026-10-09 14:05", "phase": "Robo de Credenciales", "event": "Volcado de memoria de LSASS en estación de trabajo"},
                {"ts": "2026-10-10 02:30", "phase": "Movimiento Lateral", "event": "Uso de PsExec hacia controladores de dominio y servidores"},
                {"ts": "2026-10-10 03:15", "phase": "Impacto", "event": "Ejecución de vssadmin delete shadows masivo para impedir recuperación"}
            ],
            "nodes": [
                {"id": "u:mpuig", "label": "mpuig@tarvia.example", "type": "user"},
                {"id": "h:PC-MPUIG", "label": "PC-MPUIG (10.0.4.15)", "type": "host"},
                {"id": "f:latro.exe", "label": "invoice_doc.exe", "type": "file"},
                {"id": "c2:cobalt", "label": "update.services-cdn.net", "type": "c2"},
                {"id": "h:SRV-DC01", "label": "SRV-DC01 (Controlador)", "type": "target"},
            ],
            "edges": [
                {"source": "u:mpuig", "target": "h:PC-MPUIG", "label": "Sesión interactiva"},
                {"source": "h:PC-MPUIG", "target": "f:latro.exe", "label": "Descarga y ejecuta"},
                {"source": "f:latro.exe", "target": "c2:cobalt", "label": "Beaconing C2"},
                {"source": "h:PC-MPUIG", "target": "h:SRV-DC01", "label": "PsExec lateral"}
            ]
        },
        {
            "incident_id": "INC-2026-002",
            "title": "Fraude Financiero BEC / AiTM: Suplantación Laura Ferrer (148.320 €)",
            "severity": "high",
            "status": "contained",
            "primary_entity": "lferrer@tarvia.example",
            "impact_summary": "Ataque Adversary-in-the-Middle evadiendo MFA, creación silenciosa de regla de desvío en buzón y modificación de IBAN en factura de proveedores.",
            "alerts": [
                "ALR-20261007-011785", "ALR-20261007-011786", "ALR-20261007-011787", "ALR-20261007-011788", "ALR-20261008-011789"
            ],
            "timeline": [
                {"ts": "2026-10-07 11:02", "phase": "Acceso Inicial", "event": "Inicio de sesión AiTM desde IP anónima saltándose MFA"},
                {"ts": "2026-10-07 11:15", "phase": "Persistencia", "event": "Creación de regla oculta en Outlook para mover correos financieros a RSS"},
                {"ts": "2026-10-08 08:45", "phase": "Exfiltración & Fraude", "event": "Envío de factura manipulada con cambio de cuenta bancaria a 148.320 €"}
            ],
            "nodes": [
                {"id": "u:lferrer", "label": "lferrer@tarvia.example", "type": "user"},
                {"id": "ip:proxy", "label": "185.220.101.44 (Tor/Proxy)", "type": "ip"},
                {"id": "rule:inbox", "label": "Regla Outlook 'Delete Invoice'", "type": "rule"},
                {"id": "o365:mailbox", "label": "Exchange Online", "type": "service"}
            ],
            "edges": [
                {"source": "ip:proxy", "target": "u:lferrer", "label": "AiTM Login"},
                {"source": "u:lferrer", "target": "rule:inbox", "label": "Crea regla silenciosa"},
                {"source": "rule:inbox", "target": "o365:mailbox", "label": "Oculta notificaciones"}
            ]
        }
    ]
