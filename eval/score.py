"""Evaluación contra casos etiquetados a mano.  Responsable: D (criterio).

    python -m eval.score                     # usa eval/gold.jsonl (o gold.example.jsonl si no existe)
    LLM_MODEL=mock python -m eval.score      # sin LLM, para probar el script

gold.jsonl: una línea por alerta con lo que un buen N1 concluiría:
  {"alert_id", "verdict", "severity", "escalate", "group" (id de incidente, para medir la agrupación), "nota"}

IMPORTANTE: estos casos NUNCA se pasan al agente ni se usan en los prompts. Solo miden.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from agent.triage import triage_alert

HERE = Path(__file__).parent
SEV = ["informational", "low", "medium", "high", "critical"]


def main(path: Path, use_cache: bool = True) -> None:
    gold = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    res = Counter()
    fails = []
    for g in gold:
        t = triage_alert(g["alert_id"], use_cache=use_cache)
        ok_v = t.verdict == g["verdict"]
        d_sev = abs(SEV.index(t.severity) - SEV.index(g["severity"]))
        ok_e = t.escalation.escalate == g["escalate"]
        res["verdict"] += ok_v
        res["sev_exact"] += d_sev == 0
        res["sev_pm1"] += d_sev <= 1
        res["escalate"] += ok_e
        res["fn_peligroso"] += g["verdict"] == "true_positive" and t.verdict in ("false_positive", "benign_true_positive")
        if not (ok_v and d_sev == 0 and ok_e):
            fails.append((g["alert_id"], f"{t.verdict}/{t.severity}/{t.escalation.escalate}",
                          f"{g['verdict']}/{g['severity']}/{g['escalate']}", g.get("nota", "")))
    n = len(gold)
    print(f"Casos: {n}")
    for k, label in [("verdict", "Veredicto"), ("sev_exact", "Severidad exacta"), ("sev_pm1", "Severidad ±1"), ("escalate", "Escalado")]:
        print(f"  {label:18} {res[k]}/{n}  ({res[k] / n:.0%})")
    print(f"  Incidentes reales cerrados como benignos/FP: {res['fn_peligroso']}  ← lo más grave")
    if fails:
        print("\nFallos (obtenido vs esperado):")
        for f in fails:
            print(f"  {f[0]}  {f[1]:40} esperado {f[2]:40} {f[3]}")


if __name__ == "__main__":
    p = HERE / "gold.jsonl"
    main(p if p.exists() else HERE / "gold.example.jsonl", use_cache="--fresh" not in sys.argv)
