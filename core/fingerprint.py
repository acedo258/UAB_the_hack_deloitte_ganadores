"""Huellas, patrones y atípicos.  Responsable: D (criterio).

Idea: el 95 % de las alertas son unos pocos patrones repetidos. Agrupamos por huella, el agente tría UN
representante por patrón, la persona aprueba el patrón entero, y lo que no encaja (atípicos) va a investigación.

    python -m core.fingerprint      # imprime los patrones de las 11.061 alertas

TODO (D): afinar FIELDS por regla mirando los datos; probar que ningún incidente conocido cae en un patrón de ruido.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from core.store import rows

# Campos de la evidencia (o entidades) que definen "lo mismo" para cada regla.
# Si una regla no está aquí, la huella es la FORMA de la evidencia (sus claves) + valores categóricos cortos.
FIELDS: dict[str, list[str]] = {
    "UC-WEB-001": ["evidence.action"],
    "UC-EDR-002": ["evidence.parent", "evidence.user"],
    "UC-EML-001": ["evidence.sender"],
    "UC-EDR-001": ["evidence.process_tree", "evidence.signer"],
    "UC-NET-001": ["entities.domains"],
    "UC-NET-005": ["evidence.parent_domain"],
    "UC-IDP-001": ["@keys"],
    "UC-AI-001":  ["evidence.guardrail_category", "evidence.action"],
    "UC-EDR-003": ["evidence.edr_action", "evidence.malware_name"],
    "UC-IDP-002": ["evidence.protocol", "evidence.app"],
    "UC-DLP-001": ["evidence.destination"],
    "UC-NET-006": ["evidence.parent_domain"],
    "UC-CLD-003": ["evidence.source"],
    "UC-WEB-002": ["evidence.success_count", "evidence.rate_limit"],
}
OUTLIER_MAX_SHARE = 0.02    # un patrón con < 2 % de su regla es atípico
OUTLIER_MIN_RULE = 20       # ... si la regla tiene al menos 20 alertas


def _get(a: dict, path: str):
    if path == "@keys":
        return sorted((a.get("evidence") or {}).keys())
    cur = a
    for p in path.split("."):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def fingerprint(a: dict) -> str:
    rid = a["rule_id"]
    if rid in FIELDS:
        parts = [rid] + [json.dumps(_get(a, f), ensure_ascii=False, sort_keys=True) for f in FIELDS[rid]]
    else:
        ev = a.get("evidence") or {}
        cats = {k: v for k, v in ev.items() if isinstance(v, (str, bool)) and len(str(v)) <= 25}
        parts = [rid, json.dumps(sorted(ev.keys())), json.dumps(cats, ensure_ascii=False, sort_keys=True)]
    return rid + ":" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def compute_patterns(where: str = "1=1") -> list[dict]:
    alerts = [r["raw"] for r in rows(f"SELECT raw FROM alerts WHERE {where} ORDER BY created_at")]
    groups: dict[str, list[dict]] = defaultdict(list)
    per_rule: dict[str, int] = defaultdict(int)
    for a in alerts:
        groups[fingerprint(a)].append(a)
        per_rule[a["rule_id"]] += 1
    out = []
    for fp, items in groups.items():
        rid = items[0]["rule_id"]
        n_rule = per_rule[rid]
        share = len(items) / n_rule
        out.append({
            "pattern_id": fp, "rule_id": rid, "rule_name": items[0]["rule_name"], "count": len(items),
            "rule_total": n_rule, "share": round(share, 4),
            "is_outlier": n_rule >= OUTLIER_MIN_RULE and share < OUTLIER_MAX_SHARE,
            "is_noise_candidate": len(items) >= 10,
            "first": items[0]["created_at"], "last": items[-1]["created_at"],
            "sample_alert_id": items[0]["alert_id"], "alert_ids": [x["alert_id"] for x in items],
            "signature": {f: _get(items[0], f) for f in FIELDS.get(rid, [])},
        })
    return sorted(out, key=lambda p: (-p["count"], p["rule_id"]))


if __name__ == "__main__":
    pats = compute_patterns()
    big = [p for p in pats if p["count"] >= 10]
    print(f"{sum(p['count'] for p in pats):,} alertas → {len(pats)} patrones "
          f"({len(big)} con ≥10 alertas cubren {sum(p['count'] for p in big):,}); atípicos: {sum(p['is_outlier'] for p in pats)}")
    for p in pats[:25]:
        print(f"{p['count']:>5}  {p['rule_id']:11} {json.dumps(p['signature'], ensure_ascii=False)[:90]}")
    print("\nAtípicos dentro de reglas ruidosas:")
    for p in pats:
        if p["is_outlier"]:
            print(f"{p['count']:>5}  {p['rule_id']:11} {p['sample_alert_id']}  {json.dumps(p['signature'], ensure_ascii=False)[:90]}")
