"""Informe de incidente (nivel 3) con el esquema de Deloitte (01_contexto/informe_incidente.schema.json).
Responsable: A (datos). La redacción final de root_cause la puede reescribir el LLM (B); el resto sale de los datos.

    python -m core.report                 # todos los informes (resumen) y caché en data/cache/reports.json
    python -m core.report INC-2026-004    # un informe completo en JSON
    from core.report import build_reports, get_report

Cada campo sale de datos, no del LLM:
  - patient_zero / initial_access: la primera alerta del incidente (y su táctica MITRE del catálogo).
  - timeline: cada alerta + los eventos que prueban sus comprobaciones con aviso (con event_id citable).
  - scope: usuarios, equipos, clientes, datos (de la evidencia de las alertas) e impacto de negocio
    (servicios_negocio de los activos afectados).
  - containment_plan: una acción por entidad según la tabla del apartado 4 de la política; quién aprueba lo decide
    core.policy.approval_for (lo mismo que usa el triaje). Nada sobre OT: solo escalar.
  - notifications, eradication_and_recovery, detection_gaps: reglas explícitas a partir de reglas, tácticas y datos.
  - confidence: fórmula simple y documentada (ver _confidence), no la del LLM.
Campos extra (no están en el esquema y no molestan): severity, severity_rationale, links, root_cause_source.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from core.config import CACHE_DIR, DB_PATH
from core.policy import CRIT, MATRIX, SEV, approval_for
from core.store import is_hub, norm_user, rows
from core.tools import local_time

CACHE = CACHE_DIR / "reports.json"
API_ACTIONS = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email",
               "disable_access_key"}
# Evidencia de las alertas que describe datos afectados
DATA_KEYS = ("bytes_estimated", "objects_prefix", "bucket_classification", "personal_data_matches", "matches",
             "file", "destination", "bytes_uploaded", "amount_mentioned", "requested_customer_id", "tool_result",
             "distinct_accounts", "success_count", "pci_scope", "reader", "target")
PERSONAL_DATA_RULES = {"UC-DLP-001", "UC-DLP-002", "UC-CLD-004", "UC-AI-002", "UC-WEB-003", "UC-EDR-012"}


# ------------------------------------------------------------------ datos de apoyo
def _catalog() -> dict[str, dict]:
    return {r["rule_id"]: r for r in rows("SELECT rule_id, tactica, tecnica_id, tecnica FROM catalogo")}


def _alerts(ids: list[str]) -> dict[str, dict]:
    out = {}
    for r in rows(f"SELECT alert_id, raw FROM alerts WHERE alert_id IN ({','.join('?' * len(ids))})", ids):
        out[r["alert_id"]] = r["raw"]
    return out


def _assets(hosts: list[str]) -> list[dict]:
    if not hosts:
        return []
    return rows(f"SELECT * FROM activos WHERE upper(hostname) IN ({','.join('?' * len(hosts))})", [h.upper() for h in hosts])


def _services() -> list[dict]:
    return rows("SELECT * FROM servicios_negocio")


def _service_for(asset: dict, services: list[dict]) -> dict | None:
    name = asset.get("business_service") or ""
    return next((s for s in services if s["servicio"] == name), None)


def _crit_of(alert: dict, assets_by_host: dict[str, dict]) -> str | None:
    hosts = [h.get("hostname", "").upper() for h in (alert.get("entities") or {}).get("hosts", []) or []]
    ev = alert.get("evidence") or {}
    hosts += [str(ev[k]).upper() for k in ("src", "dst") if isinstance(ev.get(k), str)]
    found = [assets_by_host[h]["criticality"] for h in hosts if h in assets_by_host and assets_by_host[h].get("criticality") in CRIT]
    return max(found, key=CRIT.index) if found else None


# ------------------------------------------------------------------ el informe
def build_report(inc: dict, others: list[dict] | None = None, with_packs: bool = True) -> dict:
    cat = _catalog()
    al = _alerts(inc["alerts"])
    nodes = inc.get("nodes", [])
    users = sorted({n["label"] for n in nodes if n["type"] == "user"})
    hosts = sorted({n["label"] for n in nodes if n["type"] == "host"})
    customers = sorted({n["label"] for n in nodes if n["type"] == "customer"})
    keys = sorted({n["label"] for n in nodes if n["type"] == "key"})
    assets = _assets(hosts)
    by_host = {a["hostname"].upper(): a for a in assets}
    services = _services()

    first = al[inc["alerts"][0]]
    f_ent = first.get("entities") or {}
    f_user = next((norm_user(u.get("upn") or u.get("username")) for u in f_ent.get("users", []) or []
                   if norm_user(u.get("upn") or u.get("username")) and not norm_user(u.get("upn") or "").startswith("(")), None)
    f_host = next((h.get("hostname") for h in f_ent.get("hosts", []) or [] if h.get("hostname")), None)
    f_cust = next((c.get("customer_id") for c in f_ent.get("customers", []) or []), None)
    patient_zero = " · ".join(x for x in (f_user, f_host, f_cust and f"cliente {f_cust}") if x) or inc.get("primary_entity", "")
    fc = cat.get(first["rule_id"], {})
    initial_access = (f"{first['rule_name']} ({first['rule_id']}, {fc.get('tecnica_id', '')} {fc.get('tecnica', '')}) "
                      f"el {local_time(first['created_at'])}; alerta {first['alert_id']}"
                      + (f"; eventos {', '.join(first.get('related_events', [])[:3])}" if first.get("related_events") else ""))

    # Cronología: cada alerta + la prueba de sus comprobaciones con aviso
    timeline, packs = [], {}
    if with_packs:
        from core.context import build_pack
        for aid in inc["alerts"]:
            try:
                packs[aid] = build_pack(aid)
            except Exception:
                pass
    for aid in inc["alerts"]:
        a = al[aid]
        c = cat.get(a["rule_id"], {})
        timeline.append({"timestamp": a["created_at"], "event_id": (a.get("related_events") or [aid])[0],
                         "description": f"{a['rule_name']} ({aid})", "mitre": c.get("tecnica_id", "")})
        p = packs.get(aid)
        if p:
            for ch in [x for x in p.checks if x.attention and x.id != "RESUMEN"][:2]:
                ev = next((e for e in ch.events if e.get("event_id") and e.get("ts")), None)
                if ev:
                    timeline.append({"timestamp": ev["ts"], "event_id": ev["event_id"],
                                     "description": f"{ch.id}: {ch.answer[:160]}", "mitre": c.get("tecnica_id", "")})
    seen, tl = set(), []
    for t in sorted(timeline, key=lambda x: x["timestamp"]):
        if (t["event_id"], t["description"][:40]) not in seen:
            seen.add((t["event_id"], t["description"][:40]))
            tl.append(t)
    timeline = tl[:40]

    # Alcance
    data_bits = []
    for aid in inc["alerts"]:
        ev = al[aid].get("evidence") or {}
        for k in DATA_KEYS:
            if ev.get(k) not in (None, "", [], {}):
                data_bits.append(f"{k}: {json.dumps(ev[k], ensure_ascii=False)[:80]}")
    impact = []
    for a in sorted(assets, key=lambda x: -CRIT.index(x["criticality"]) if x.get("criticality") in CRIT else 0):
        s = _service_for(a, services)
        line = (f"{a['hostname']}: {a.get('type', '')}, criticidad {a.get('criticality')}"
                + (f" — {s['servicio']} ({s['impacto']}; responsable: {s['responsable']})" if s
                   else f" — {a.get('business_service') or 'sin servicio en el inventario'}"))
        impact.append(line)
    if customers:
        impact.append(f"{len(customers)} cuentas de cliente afectadas")
    scope = {"users": users, "hosts": hosts, "customers": customers, "cloud_keys": keys,
             "data": "; ".join(dict.fromkeys(data_bits)) or "sin datos afectados identificados en la evidencia de las alertas",
             "business_impact": "; ".join(impact) or "sin servicio de negocio identificado en el inventario"}

    # Severidad del incidente con la matriz (criticidad real de los activos de cada alerta)
    sev, why = "informational", ""
    for aid in inc["alerts"]:
        a = al[aid]
        crit = _crit_of(a, by_host)
        s = MATRIX.get(a["severity"], MATRIX["medium"])[CRIT.index(crit) if crit in CRIT else 1]
        if SEV.index(s) > SEV.index(sev):
            sev, why = s, f"{aid}: regla {a['severity']} × activo {crit or 'Media (sin activo en la CMDB)'} = {s}"

    rules = set(inc.get("rules") or Counter(al[a]["rule_id"] for a in inc["alerts"]))
    tactics = {cat.get(r, {}).get("tactica") for r in rules}
    report = {
        "incident_id": inc["incident_id"],
        "title": inc["title"],
        "alert_ids": inc["alerts"],
        "related_incidents": _related(inc, others or []),
        "patient_zero": patient_zero,
        "initial_access": initial_access,
        "timeline": timeline,
        "scope": scope,
        "root_cause": _root_cause(inc, first, fc, users, hosts, tactics),
        "root_cause_source": "datos (borrador; lo puede reescribir el agente)",
        "containment_plan": _containment(nodes, assets, al, inc),
        "eradication_and_recovery": _eradication(rules, tactics, scope),
        "notifications": _notifications(rules, sev, scope, users, assets),
        "detection_gaps": _gaps(inc, al, timeline),
        "confidence": _confidence(inc),
        "open_questions": _questions(inc, packs, scope),
        "severity": sev,
        "severity_rationale": why,
        "links": inc.get("links", []),
    }
    return report


def _related(inc: dict, others: list[dict]) -> list[str]:
    def strong(n):   # identidades y también indicadores externos (no hubs, no IPs internas): unen campañas del mismo atacante
        if n["type"] in ("user", "host", "key", "customer", "file", "c2"):
            return True
        return n["type"] in ("ip", "domain") and not re.match(r"^(10\.|172\.16\.|192\.168\.)", n["label"])
    mine = {n["label"] for n in inc.get("nodes", []) if strong(n)}
    out = []
    for o in others:
        if o["incident_id"] == inc["incident_id"]:
            continue
        common = sorted(mine & {n["label"] for n in o.get("nodes", [])})
        if common:
            out.append(f"{o['incident_id']} (comparte {', '.join(common[:3])})")
    return out


def _root_cause(inc, first, fc, users, hosts, tactics) -> str:
    phases = inc["title"].split(" · ")[0]
    who = ", ".join((users + hosts)[:4])
    return (f"Borrador a partir de los datos: el incidente empieza con {first['rule_name'].lower()} "
            f"({fc.get('tecnica', 'técnica sin catalogar')}) el {local_time(first['created_at'])} y recorre las fases "
            f"{phases}. Entidades implicadas: {who or inc.get('primary_entity', '')}. "
            "La causa raíz definitiva (qué control falló) debe confirmarla el analista o redactarla el agente con este contexto.")


def _containment(nodes: list[dict], assets: list[dict], al: dict, inc: dict) -> list[dict]:
    """Una acción por entidad según el apartado 4 de la política. Quién aprueba: core.policy.approval_for."""
    services = _services()
    by_host = {a["hostname"].upper(): a for a in assets}
    plan: list[dict] = []

    def add(action, target, reason, impact="", kind=""):
        if any(p["action"] == action and p["target"] == target for p in plan):
            return
        req, who, note = approval_for(action, target, assets)
        plan.append({"action": action, "target": target, "approver": who or "N1 (sin aprobación)", "requires_approval": req,
                     "business_impact": impact or note or "", "reason": reason,
                     "executable": action in API_ACTIONS and who != "Responsable de Operaciones", "_kind": kind})

    for n in nodes:
        t, e = n["type"], n["label"]
        if t == "host":
            a = by_host.get(e.upper())
            if a and a.get("zone") == "LOGISTICS-OT":
                plan.append({"action": "escalate", "target": e, "approver": "Responsable de Operaciones", "requires_approval": True,
                             "business_impact": "Red OT: el SOC nunca actúa; solo escalar", "reason": "activo OT implicado",
                             "executable": False})
                continue
            s = _service_for(a, services) if a else None
            add("isolate_host", e, "equipo implicado en la cadena",
                f"{s['servicio']}: {s['impacto']}" if s else
                (f"{a.get('type', 'equipo')}: {a.get('business_service') or 'sin servicio en el inventario'}" if a else "equipo fuera de la CMDB"))
        elif t == "user":
            if e.startswith("svc_"):
                add("disable_user", e, "cuenta de servicio usada por el atacante", "Cuenta de servicio: puede parar un proceso de negocio")
            elif not re.match(r"^[a-z0-9._\-]+$", e):
                continue
            else:
                add("revoke_sessions", e, "sesiones posiblemente en manos del atacante", "el usuario pierde sus sesiones abiertas", "user")
                add("reset_password", e, "credenciales expuestas", "el usuario debe cambiar la contraseña", "user")
        elif t == "key":
            add("disable_access_key", e, "clave cloud usada por el atacante", "lo que use esa clave deja de funcionar")
        elif t in ("c2", "domain", "ip"):
            if is_hub(e, include_campaigns=True) or re.match(r"^(10\.|172\.16\.|192\.168\.)", e):
                continue
            add("block_ioc", e, "indicador externo del incidente")
        elif t == "email":
            add("purge_email", e, "correo malicioso en los buzones")
        elif t == "customer":
            add("reset_password", e, "cuenta de cliente tomada o expuesta",
                "el cliente debe restablecer su contraseña; revisar compras y cambios de datos recientes")
    # Identidades cloud creadas por el atacante (aparecen como usuario sin estar en el directorio)
    known = {r["u"] for r in rows("SELECT lower(username) u FROM usuarios")}
    for p in plan:
        if p["_kind"] == "user" and p["action"] in ("revoke_sessions", "reset_password") and p["target"] not in known:
            p.update(action="disable_user", reason="identidad que no está en el directorio (posiblemente creada por el atacante)",
                     business_impact="")
    order = {"block_ioc": 0, "purge_email": 1, "revoke_sessions": 2, "reset_password": 3, "disable_access_key": 4,
             "disable_user": 5, "isolate_host": 6, "escalate": 7}
    for p in plan:
        p.pop("_kind", None)
    uniq = {(p["action"], p["target"]): p for p in plan}
    return sorted(uniq.values(), key=lambda p: (order.get(p["action"], 9), p["target"]))[:15]


def _eradication(rules: set[str], tactics: set, scope: dict) -> list[str]:
    out = []
    if "Persistence" in tactics or rules & {"UC-IDP-005", "UC-IDP-008", "UC-CLD-002"}:
        out.append("Retirar la persistencia: reglas de buzón, altas en grupos privilegiados, usuarios y claves cloud creados")
    if "Credential Access" in tactics or rules & {"UC-EDR-004", "UC-IDP-006", "UC-IDP-002", "UC-WEB-002"}:
        out.append("Rotar todas las credenciales expuestas (usuarios, cuentas de servicio, tokens y claves)")
    if "Execution" in tactics or rules & {"UC-EDR-001", "UC-EDR-006", "UC-EDR-012", "UC-EDR-009"}:
        out.append("Reinstalar o restaurar desde imagen limpia los equipos donde hubo ejecución")
    if "Impact" in tactics or "UC-EDR-007" in rules:
        out.append("Verificar copias de seguridad y restaurar lo afectado; comprobar que el EDR vuelve a estar activo en todos los equipos")
    if rules & {"UC-DEV-001"}:
        out.append("Fijar el registro interno para los paquetes @tarvia/* y revisar los builds publicados con la dependencia falsa")
    if rules & {"UC-AI-002", "UC-AI-001"}:
        out.append("Revisar el control de autorización de herramientas del asistente (que una herramienta no acepte otro customer_id)")
    out.append("Vigilar 30 días la reaparición de los indicadores y entidades del incidente")
    return out


def _notifications(rules, sev, scope, users, assets) -> list[str]:
    out = []
    if rules & PERSONAL_DATA_RULES or scope["customers"]:
        out.append("DPO: posible brecha de datos personales; si se confirma, notificable a la AEPD y a la CNPD en 72 h desde su conocimiento")
    if "UC-EDR-012" in rules or any(str(a.get("business_service", "")).find("PCI") >= 0 for a in assets):
        out.append("Adquirente de pagos / responsable PCI DSS: posible compromiso de datos de tarjeta en TPV")
    if "UC-EML-004" in rules:
        out.append("Tesorería: retener cualquier pago al proveedor con cambio de IBAN no verificado")
    if "UC-WEB-003" in rules:
        out.append("Equipo de fraude e-commerce: compras con tarjetas regalo en cuentas tomadas")
    if any(u.startswith("ext.") for u in users):
        out.append("Proveedor afectado (responsable del contrato), por uso de su cuenta")
    if any(a.get("zone") == "LOGISTICS-OT" for a in assets):
        out.append("Responsable de Operaciones (Martorell): actividad en la red OT")
    if sev in ("high", "critical"):
        out.append("CISO (Alba Rovira)")
    out.append("N2 de guardia por teléfono si es fuera de horario (SOC de 8:00 a 20:00 de lunes a viernes)")
    return out


def _gaps(inc, al, timeline) -> list[str]:
    out = []
    low = [a for a in inc["alerts"] if al[a]["severity"] in ("informational", "low")]
    if low and any(al[a]["severity"] in ("high", "critical") for a in inc["alerts"]):
        out.append(f"{len(low)} alerta(s) de la cadena salieron con severidad baja ({', '.join(sorted({al[a]['rule_id'] for a in low}))}): "
                   "revisar si deberían subir cuando coinciden con otras señales de la misma entidad")
    derived = [l for l in inc.get("links", []) if all(f != "alerta" for f in l.get("from", []))]
    for l in derived[:3]:
        out.append(f"La relación por {l['type']} {l['entity']} solo apareció al investigar los logs ({', '.join(l['from'])}); "
                   "considerar una regla que la detecte directamente")
    t0, t_high = al[inc["alerts"][0]]["created_at"], next(
        (al[a]["created_at"] for a in inc["alerts"] if al[a]["severity"] in ("high", "critical")), None)
    if t_high and t_high != t0:
        h = (datetime.fromisoformat(t_high.replace("Z", "+00:00")) - datetime.fromisoformat(t0.replace("Z", "+00:00"))).total_seconds() / 3600
        if h >= 1:
            out.append(f"Pasaron {h:.0f} h entre la primera alerta y la primera de severidad alta: el aviso temprano tenía severidad baja o media")
    return out or ["Sin huecos evidentes con los datos disponibles"]


def _confidence(inc) -> float:
    """0,5 de base; +0,1 por cada tipo de identidad distinta que une (usuario, clave, fichero, cliente, sesión);
    +0,1 si alguna unión la descubrió una receta; -0,1 si solo une infraestructura (equipo, IP, dominio). Máx. 0,95."""
    types = {l["type"] for l in inc.get("links", [])}
    ident = types & {"user", "access_key", "file", "hash", "customer", "session", "message_id"}
    c = 0.5 + 0.1 * len(ident)
    if any(f.startswith("receta") for l in inc.get("links", []) for f in l.get("from", [])):
        c += 0.1
    if not ident:
        c -= 0.1
    return round(max(0.3, min(0.95, c)), 2)


def _questions(inc, packs, scope) -> list[str]:
    out = [f"¿Hay actividad de {inc.get('primary_entity', 'las entidades del incidente')} posterior a {local_time(inc['last_seen'])}?"]
    for aid, p in packs.items():
        for c in p.checks:
            if c.answer.startswith("no se pudo comprobar"):
                out.append(f"{aid}: {c.id} no se pudo comprobar")
    if "sin datos afectados" in scope["data"]:
        out.append("¿Salió algún dato de la organización? La evidencia de las alertas no lo concreta")
    return out[:6]


# ------------------------------------------------------------------ caché y CLI
def build_reports(refresh: bool = False) -> list[dict]:
    from core.correlate import compute_incidents
    stamp = DB_PATH.stat().st_mtime if DB_PATH.exists() else 0
    if not refresh and CACHE.exists():
        try:
            data = json.loads(CACHE.read_text(encoding="utf-8"))
            if data.get("db_mtime") == stamp:
                return data["reports"]
        except (ValueError, KeyError):
            pass
    incs = compute_incidents()
    reports = [build_report(i, incs) for i in incs]
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps({"db_mtime": stamp, "computed_at": datetime.now(timezone.utc).isoformat(), "reports": reports},
                                ensure_ascii=False, default=str), encoding="utf-8")
    return reports


def get_report(incident_id: str) -> dict | None:
    return next((r for r in build_reports() if r["incident_id"] == incident_id), None)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].startswith("INC-"):
        print(json.dumps(get_report(sys.argv[1]), ensure_ascii=False, indent=2, default=str))
    else:
        for r in build_reports(refresh="--refresh" in sys.argv):
            acts = Counter(p["action"] for p in r["containment_plan"])
            print(f"{r['incident_id']}  {r['severity']:<8} conf {r['confidence']}  {len(r['alert_ids'])} alertas · "
                  f"paciente cero: {r['patient_zero']}\n      contención: {dict(acts)} · notificar: {len(r['notifications'])} · "
                  f"relacionados: {r['related_incidents'] or '—'}")
