"""Cobertura del pack: ¿trae el expediente los eventos que prueban cada caso?  Lo ejecuta D (criterio).

    python -m eval.pack_coverage                       # usa eval/gold.jsonl
    python -m eval.pack_coverage mis_casos.jsonl

Cada línea del fichero necesita "alert_id". Los eventos esperados se toman de "events" (lista) si existe;
si no, de cualquier identificador de evento (EDR-0123400, SIGN-0083865…) escrito en los demás campos de texto,
por ejemplo en la "nota" del gold.

La salida SOLO muestra alert_id, eventos que faltan y su fuente: nunca veredicto, severidad ni notas. Así D puede
pasársela a A para mejorar el contexto sin filtrar el gold (que no debe llegar ni a prompts ni a recetas).
Escribe además data/pack_coverage.csv.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

from core.config import DB_PATH
from core.tools import PREFIX_SOURCE

HERE = Path(__file__).parent
OUT = DB_PATH.parent / "pack_coverage.csv"
EVENT_RE = re.compile(r"\b(" + "|".join(sorted(PREFIX_SOURCE, key=len, reverse=True)) + r")-\d{4,8}\b")


def expected_events(case: dict) -> list[str]:
    if isinstance(case.get("events"), list):
        return [e for e in case["events"] if isinstance(e, str)]
    text = " ".join(str(v) for k, v in case.items() if k != "alert_id" and isinstance(v, (str, list)))
    return sorted(set(m.group(0) for m in EVENT_RE.finditer(text)))


def exists(event_id: str) -> bool:
    from core.store import rows
    src = PREFIX_SOURCE.get(event_id.split("-")[0])
    return bool(src and rows(f"SELECT 1 FROM {src} WHERE event_id = ? LIMIT 1", [event_id]))


def check(alert_id: str, events: list[str]) -> dict:
    from core.context import build_pack
    blob = json.dumps(build_pack(alert_id).model_dump(exclude={"trace"}), ensure_ascii=False, default=str)
    missing = [e for e in events if e not in blob]
    return {"alert_id": alert_id, "expected": len(events), "found": len(events) - len(missing),
            "missing": [{"event_id": e, "source": PREFIX_SOURCE.get(e.split("-")[0], "?"),
                         "exists_in_db": exists(e)} for e in missing]}


def main(path: Path) -> None:
    cases = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    results, no_events = [], 0
    for case in cases:
        evs = expected_events(case)
        if not evs:
            no_events += 1
            continue
        results.append(check(case["alert_id"], evs))

    full = sum(1 for r in results if not r["missing"])
    tot = sum(r["expected"] for r in results)
    found = sum(r["found"] for r in results)
    print(f"{len(results)} casos con eventos esperados ({no_events} sin eventos citados, no se miden)")
    print(f"casos con TODOS sus eventos en el pack: {full}/{len(results)} · eventos encontrados: {found}/{tot}"
          + (f" ({found / tot:.0%})" if tot else ""))
    by_src = Counter(m["source"] for r in results for m in r["missing"])
    if by_src:
        print("eventos que faltan por fuente:", ", ".join(f"{k} {v}" for k, v in by_src.most_common()))
    for r in results:
        if r["missing"]:
            print(f"  {r['alert_id']}: faltan " + ", ".join(
                f"{m['event_id']} ({m['source']}{'' if m['exists_in_db'] else ', NO existe en la base'})" for m in r["missing"]))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["alert_id", "expected", "found", "missing_event_ids", "missing_sources"])
        for r in results:
            w.writerow([r["alert_id"], r["expected"], r["found"], " ".join(m["event_id"] for m in r["missing"]),
                        " ".join(sorted({m["source"] for m in r["missing"]}))])
    print(f"\nDetalle: {OUT}  (solo identificadores: se puede compartir con A)")


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "gold.jsonl"
    main(p)
