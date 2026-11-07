"""Prueba a escala del pack de contexto (parte A): genera el pack de muchas alertas y mide cada una.

    python -m eval.measure_packs                 # las 11.061 alertas, tantos procesos como CPUs
    python -m eval.measure_packs --dev           # solo las 150 de desarrollo
    python -m eval.measure_packs --limit 500 --workers 4

Escribe data/measure_packs.csv (una fila por alerta) y muestra un resumen:
  - tiempo y tamaño del pack (objetivos: < 1 s y <= PACK_MAX_CHARS)
  - errores de recetas o comparaciones
  - por regla: cuántas alertas tienen algún aviso (attention) y cuáles avisan más

Sirve también a D: las reglas con 0 % de avisos son candidatas a patrón de ruido; un aviso en una regla
muy ruidosa es candidato a atípico. Esto NO es evaluación de veredictos (eso es eval/score.py).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor

from core.config import DB_PATH, PACK_MAX_CHARS

OUT = DB_PATH.parent / "measure_packs.csv"
FIELDS = ["alert_id", "rule_id", "runbook", "ms", "chars", "checks", "attention", "attention_ids", "errors", "timeline", "notes"]


def _measure(alert_id: str) -> dict:
    from core.context import build_pack
    t = time.time()
    try:
        p = build_pack(alert_id)
    except Exception as e:  # un pack que no se puede construir es un fallo que hay que ver
        return {"alert_id": alert_id, "rule_id": "", "runbook": "", "ms": int((time.time() - t) * 1000), "chars": 0,
                "checks": 0, "attention": 0, "attention_ids": "", "errors": f"build_pack: {type(e).__name__}: {e}"[:200],
                "timeline": 0, "notes": ""}
    ms = int((time.time() - t) * 1000)
    att = [c.id for c in p.checks if c.attention]
    errs = [c.id for c in p.checks if c.answer.startswith(("no se pudo", "error"))]
    return {"alert_id": alert_id, "rule_id": p.alert.get("rule_id", ""), "runbook": p.runbook_id, "ms": ms,
            "chars": len(json.dumps(p.model_dump(exclude={"trace"}), ensure_ascii=False, default=str)),
            "checks": len(p.checks), "attention": len(att), "attention_ids": " ".join(att), "errors": " ".join(errs),
            "timeline": len(p.timeline), "notes": len(p.notes)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", action="store_true", help="solo las alertas de desarrollo")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    args = ap.parse_args()

    from core.store import rows
    where = "WHERE dev_sample " if args.dev else ""
    ids = [r["alert_id"] for r in rows(f"SELECT alert_id FROM alerts {where}ORDER BY created_at")]
    if args.limit:
        ids = ids[: args.limit]
    print(f"Midiendo {len(ids):,} alertas con {args.workers} procesos…", flush=True)

    t0, out = time.time(), []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for i, r in enumerate(ex.map(_measure, ids, chunksize=25), 1):
            out.append(r)
            if i % 500 == 0:
                el = time.time() - t0
                print(f"  {i:,}/{len(ids):,} · {el:.0f} s · faltan ~{el / i * (len(ids) - i):.0f} s", flush=True)

    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(out)

    ms = [r["ms"] for r in out]
    ch = [r["chars"] for r in out]
    bad = [r for r in out if r["errors"]]
    over = [r for r in out if r["chars"] > PACK_MAX_CHARS or r["ms"] > 1000]
    print(f"\n{len(out):,} alertas en {time.time() - t0:.0f} s")
    print(f"tiempo: media {statistics.mean(ms):.0f} ms · p95 {sorted(ms)[int(len(ms) * .95)]} ms · máx {max(ms)} ms")
    print(f"tamaño: media {statistics.mean(ch):.0f} · máx {max(ch)} (límite {PACK_MAX_CHARS})")
    print(f"fuera de objetivo (> 1 s o > límite): {len(over)} · con errores: {len(bad)}")
    for r in bad[:5]:
        print("  error:", r["alert_id"], r["rule_id"], r["errors"])

    by_rule: dict[str, list[dict]] = defaultdict(list)
    for r in out:
        by_rule[r["rule_id"]].append(r)
    print(f"\n{'regla':<12}{'alertas':>8}{'con aviso':>11}  avisos más frecuentes")
    for rule, rs in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
        n_att = sum(1 for r in rs if r["attention"])
        top = Counter(x for r in rs for x in r["attention_ids"].split()).most_common(3)
        print(f"{rule:<12}{len(rs):>8}{n_att / len(rs):>10.0%}  " + ", ".join(f"{k} {v}" for k, v in top))
    print(f"\nDetalle por alerta: {OUT}")


if __name__ == "__main__":
    main()
