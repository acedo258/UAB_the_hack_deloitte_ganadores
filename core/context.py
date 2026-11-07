"""Construye el ContextPack de una alerta: lo que haría un N1 en los pasos 2-4 del runbook.  Responsable: A.

    from core.context import build_pack
    pack = build_pack("ALR-20261009-011793")

Determinista y rápido (< 1 s). El agente recibe esto ya masticado; en modo investigador puede pedir más.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import timedelta

from core.config import PACK_MAX_CHARS
from core.schemas import ContextPack, IntelResult, UntrustedField
from core.store import alert_entities, rows
from core.tools import ToolBox, _intel_summary, _iso, local_time

INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/16")]

# Campos que puede escribir un atacante (o un cliente): nunca se obedecen
UNTRUSTED_KEYS = {"subject", "body_excerpt", "email_body_excerpt", "prompt", "prompt_excerpt", "service_description",
                  "response_summary", "rule_name_user", "file_name", "message", "stdout", "user_agent", "new_user_agent",
                  "display_name_remote", "comment", "notes"}
# Señales de que el texto intenta dar órdenes a un sistema automático
INJECTION_RE = re.compile(
    r"(clasific|false.?positive|no escal|no bloque|ignor|instruc|system prompt|sistema automatizado|"
    r"aprobado por el equipo|no requiere revisi|you are|act as|disregard|override|display\s*:\s*none)", re.I)


def is_internal(ip: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in n for n in INTERNAL_NETS)
    except ValueError:
        return False


def _walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def find_untrusted(obj, prefix: str) -> list[UntrustedField]:
    out = []
    for path, val in _walk(obj, prefix):
        if not isinstance(val, str) or len(val) < 4:
            continue
        key = re.sub(r"\[\d+\]", "", path.split(".")[-1])
        hit = INJECTION_RE.search(val)
        if key in UNTRUSTED_KEYS or hit:
            out.append(UntrustedField(path=path, text=val[:500], suspicious=bool(hit),
                                      reason=f"patrón «{hit.group(0)}»" if hit else "texto controlado por terceros"))
    return out


def build_pack(alert_id: str, alert: dict | None = None, tb: ToolBox | None = None) -> ContextPack:
    tb = tb or ToolBox()
    a = alert or tb.get_alert(alert_id)
    if a is None:
        raise KeyError(alert_id)
    t = _iso(a["created_at"])
    d24, d7 = timedelta(hours=24), timedelta(days=7)
    ents = alert_entities(a)
    by_type: dict[str, list[str]] = {}
    for e, et in ents:
        by_type.setdefault(et, []).append(e)
    notes: list[str] = []

    rule = rows("SELECT * FROM catalogo WHERE rule_id = ?", [a["rule_id"]])

    assets = []
    for h in by_type.get("host", [])[:4]:
        assets += tb.get_asset(h)
    # Hosts que aparecen solo en la evidencia (src/dst de movimiento lateral, OT...)
    for k in ("src", "dst"):
        v = (a.get("evidence") or {}).get(k)
        if isinstance(v, str) and re.match(r"^[A-Z][A-Z0-9\-]+$", v) and v not in {x["hostname"] for x in assets}:
            assets += tb.get_asset(v)

    users = [u for u in (tb.get_user(x) for x in by_type.get("user", [])[:4]) if u]
    if by_type.get("user") and not users:
        notes.append("Usuario no encontrado en el directorio")

    intel: list[IntelResult] = []
    indicators = [(i, "ip") for i in by_type.get("ip", []) if not is_internal(i)] + \
                 [(d, "domain") for d in by_type.get("domain", [])] + [(h, "sha256") for h in by_type.get("hash", [])]
    for ind, typ in indicators[:6]:
        r = tb.intel(ind)
        mal = True if (r["tip"] and r["tip"]["reputation"] == "malicious") or (r["sandbox"] and r["sandbox"]["verdict"] == "malicious") else None
        intel.append(IntelResult(indicator=ind, type=typ, source="ti_feed+geoip+sandbox", result=_intel_summary(r), malicious=mal))

    change_keys = [e for e, _ in ents] + [str(v) for k, v in (a.get("evidence") or {}).items()
                                          if k in ("src", "dst", "account", "recipient", "by", "from_host", "change_ticket", "maintenance_window", "firewall_rule")]
    changes = tb.matching_changes(change_keys, a["created_at"], alert_text=json.dumps(a, ensure_ascii=False))
    # Si la alerta cita un ticket de cambio, comprobamos que existe de verdad
    for k, v in (a.get("evidence") or {}).items():
        if isinstance(v, str) and re.match(r"^(CHG|FLUJO)-", v) and not any(c["id"] == v for c in changes):
            exists = rows("SELECT id FROM calendario_cambios WHERE id = ?", [v])
            notes.append(f"La alerta cita {v}: {'existe pero no encaja en fecha/alcance' if exists else 'NO existe en el calendario'}")

    related = tb.get_events(a.get("related_events", []))

    # Línea temporal ±24 h de las entidades principales (usuarios y hosts primero)
    main = (by_type.get("user", []) + by_type.get("host", []) + by_type.get("customer", []) +
            [i for i in by_type.get("ip", []) if not is_internal(i)] + by_type.get("access_key", []))[:3]
    timeline = []
    rel_ids = set(a.get("related_events", []))
    for e in main:
        tl = tb.entity_timeline(e, (t - d24).isoformat(), (t + d24).isoformat(), limit=15)
        timeline += [{"entity": e, **ev} for ev in tl["events"] if ev["event_id"] not in rel_ids]
        if tl["truncated"]:
            notes.append(f"Línea temporal de {e} recortada: {tl['counts']}")

    other = []
    for e in main:
        other += tb.alerts_for_entity(e, (t - d7).isoformat(), (t + d7).isoformat(), exclude=a["alert_id"], limit=8)
    other = list({o["alert_id"]: o for o in other}.values())[:12]

    untrusted = find_untrusted(a.get("evidence", {}), "alert.evidence") + find_untrusted(related, "related_events")

    pack = ContextPack(alert=a, entities=a.get("entities", {}) or {}, runbook_id=a.get("runbook", ""), rule_info=rule[0] if rule else {},
                       local_time=local_time(a["created_at"]), assets=assets, users=users, matching_changes=changes,
                       intel=intel, related_events=related, timeline=timeline, other_alerts=other,
                       untrusted_fields=untrusted, notes=notes)
    _fit(pack)
    pack.trace = list(tb.trace)
    return pack


def _fit(pack: ContextPack) -> None:
    """Recorta el pack hasta PACK_MAX_CHARS quitando primero línea temporal y luego otras alertas."""
    def size():
        return len(json.dumps(pack.model_dump(exclude={"trace"}), ensure_ascii=False, default=str))
    while size() > PACK_MAX_CHARS and pack.timeline:
        pack.timeline = pack.timeline[: max(0, len(pack.timeline) - 5)]
        if "Línea temporal recortada por tamaño" not in pack.notes:
            pack.notes.append("Línea temporal recortada por tamaño")
    while size() > PACK_MAX_CHARS and len(pack.other_alerts) > 3:
        pack.other_alerts = pack.other_alerts[:-3]
    for u in pack.users:          # campos que no aportan
        for k in ("user_id", "created"):
            u.pop(k, None)
