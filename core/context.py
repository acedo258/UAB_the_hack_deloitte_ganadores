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
from core.baseline import run_baselines
from core.recipes import Ctx as RecipeCtx, run_recipes
from core.store import alert_entities, is_hub, rows
from core.tools import ToolBox, _intel_summary, _iso, local_time

TIMELINE_MIN = 8          # eventos de línea temporal que se intentan conservar al recortar
# Fuentes de la línea temporal: lo que HIZO la entidad, no su tráfico de red
TIMELINE_SOURCES = ["ad_events", "ai_gateway", "cicd_builds", "cloudtrail", "dlp", "ecom_account", "ecom_auth",
                    "edr_events", "email", "email_clicks", "idp_audit", "idp_signins", "sql_audit", "vpn"]
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
    candidates = (by_type.get("user", []) + by_type.get("host", []) + by_type.get("customer", []) +
                  [i for i in by_type.get("ip", []) if not is_internal(i)] + by_type.get("access_key", []))
    # Fuera los hubs (DC01, la salida de Orange, nt authority\system...): su línea temporal es ruido
    skipped = [e for e in candidates if is_hub(e)]
    if skipped:
        notes.append(f"Excluidas por ser hubs (las comparte demasiada gente para relacionar nada): {', '.join(skipped[:5])}")
    main = [e for e in candidates if not is_hub(e)][:3]
    timeline = []
    rel_ids = set(a.get("related_events", []))
    for e in main:
        # Sin tráfico de red (proxy, DNS, firewall, WAF): son miles de líneas y ya lo resumen las recetas y BL.host_domain
        tl = tb.entity_timeline(e, (t - d24).isoformat(), (t + d24).isoformat(), limit=15, sources=TIMELINE_SOURCES)
        timeline += [{"entity": e, **ev} for ev in tl["events"] if ev["event_id"] not in rel_ids]
        if tl["truncated"]:
            notes.append(f"Línea temporal de {e} recortada: {tl['counts']}")

    other = []
    for e in main:
        other += tb.alerts_for_entity(e, (t - d7).isoformat(), (t + d7).isoformat(), exclude=a["alert_id"], limit=8)
    other = list({o["alert_id"]: o for o in other}.values())[:12]

    # Recetas del runbook: las comprobaciones concretas, ya resueltas (core/recipes.py)
    checks = run_recipes(a, by_type, tb)
    # Comparación con lo habitual ("¿es la primera vez que…?"), para cualquier alerta (core/baseline.py)
    cx = RecipeCtx(a, by_type, tb)
    checks += run_baselines(a, by_type, tb, cx.users(), cx.hosts(), cx.ext_ips(20))

    untrusted = (find_untrusted(a.get("evidence", {}), "alert.evidence") + find_untrusted(related, "related_events")
                 + find_untrusted([ch.events for ch in checks], "checks"))

    pack = ContextPack(alert=a, entities=a.get("entities", {}) or {}, runbook_id=a.get("runbook", ""), rule_info=rule[0] if rule else {},
                       local_time=local_time(a["created_at"]), assets=assets, users=users, matching_changes=changes,
                       intel=intel, related_events=related, timeline=timeline, other_alerts=other, checks=checks,
                       untrusted_fields=untrusted, notes=notes)
    _fit(pack)
    pack.trace = list(tb.trace)
    return pack


def _fit(pack: ContextPack) -> None:
    """Recorta el pack hasta PACK_MAX_CHARS. Orden: línea temporal hasta un mínimo, otras alertas,
    eventos de apoyo de las comprobaciones (nunca su respuesta) y, solo al final, el resto de la línea temporal."""
    def size():
        return len(json.dumps(pack.model_dump(exclude={"trace"}), ensure_ascii=False, default=str))

    def note(msg):
        if msg not in pack.notes:
            pack.notes.append(msg)

    def trim_timeline(floor):
        while size() > PACK_MAX_CHARS and len(pack.timeline) > floor:
            pack.timeline = pack.timeline[: max(floor, len(pack.timeline) - 5)]
            note("Línea temporal recortada por tamaño")

    trim_timeline(TIMELINE_MIN)
    while size() > PACK_MAX_CHARS and len(pack.other_alerts) > 3:
        pack.other_alerts = pack.other_alerts[:-3]
    while size() > PACK_MAX_CHARS and any(len(c.events) > 2 for c in pack.checks):
        for c in pack.checks:
            if len(c.events) > 2:
                c.events = c.events[:-1]
        note("Eventos de apoyo de las comprobaciones recortados por tamaño")
    trim_timeline(0)
    # Último recurso (p. ej. credential stuffing con decenas de eventos relacionados): eventos relacionados y texto
    # no fiable, conservando primero lo sospechoso
    while size() > PACK_MAX_CHARS and len(pack.related_events) > 5:
        pack.related_events = pack.related_events[:-3]
        note("Eventos relacionados recortados por tamaño")
    if size() > PACK_MAX_CHARS:
        pack.untrusted_fields = sorted(pack.untrusted_fields, key=lambda u: not u.suspicious)
        for u in pack.untrusted_fields:
            u.text = u.text[:200]
        while size() > PACK_MAX_CHARS and len(pack.untrusted_fields) > 5 and not pack.untrusted_fields[-1].suspicious:
            pack.untrusted_fields.pop()
        note("Texto no fiable recortado por tamaño (los sospechosos se conservan)")
    for u in pack.users:          # campos que no aportan
        for k in ("user_id", "created"):
            u.pop(k, None)
