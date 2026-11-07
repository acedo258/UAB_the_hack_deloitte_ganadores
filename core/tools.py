"""Herramientas de consulta del SOC.  Responsable: A (datos).

Cada herramienta:
  - devuelve datos COMPACTOS (recuentos + los N primeros), para no gastar tokens;
  - queda registrada en la traza (TraceStep) para que la consola enseñe "qué consultó la IA".

Uso:
    tb = ToolBox()
    tb.get_asset("WS-BCN-1770"); tb.intel("107.174.115.43")
    tb.trace   -> lista de TraceStep

TOOL_SPECS describe las herramientas en formato OpenAI function-calling para el modo investigador.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from core.schemas import TraceStep
from core.store import hubs, is_hub, norm_user, rows

PREFIX_SOURCE = {
    "ADE": "ad_events", "AIG": "ai_gateway", "CI": "cicd_builds", "CT": "cloudtrail", "DLP": "dlp", "DNS": "dns",
    "ECO": "ecom_account", "ECA": "ecom_auth", "EDR": "edr_events", "EML": "email", "CLK": "email_clicks",
    "FW": "firewall", "AUD": "idp_audit", "SIGN": "idp_signins", "PRX": "proxy", "SQL": "sql_audit",
    "VPN": "vpn", "WAF": "waf",
}
SOURCES = sorted(set(PREFIX_SOURCE.values()))


def _iso(ts: str | datetime) -> datetime:
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def local_time(ts: str) -> str:
    """Hora de España. UTC+2 hasta el 25/10/2026 a las 01:00 UTC; UTC+1 después."""
    t = _iso(ts)
    off = 2 if t < datetime(2026, 10, 25, 1, tzinfo=timezone.utc) else 1
    lt = t + timedelta(hours=off)
    dias = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
    return f"{dias[lt.weekday()]} {lt:%d/%m %H:%M} (UTC+{off})"


def compact(ev: dict[str, Any], max_len: int = 260) -> str:
    """Una línea legible de un evento: quita campos vacíos y recorta."""
    d = {k: v for k, v in ev.items() if v not in (None, "", [], {}) and k not in ("ts",)}
    s = json.dumps(d, ensure_ascii=False, default=str)
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


class ToolBox:
    def __init__(self) -> None:
        self.trace: list[TraceStep] = []

    # ------------------------------------------------------------ registro
    def _run(self, name: str, args: dict, fn: Callable[[], Any], summarize: Callable[[Any], str]) -> Any:
        t = time.time()
        result = fn()
        self.trace.append(TraceStep(step=len(self.trace) + 1, kind="tool", tool=name, input=args,
                                    result_summary=summarize(result), ms=int((time.time() - t) * 1000),
                                    ts=datetime.now(timezone.utc).isoformat()))
        return result

    # ------------------------------------------------------------ alertas
    def get_alert(self, alert_id: str) -> dict | None:
        def f():
            r = rows("SELECT raw FROM alerts WHERE alert_id = ?", [alert_id])
            return r[0]["raw"] if r else None
        return self._run("get_alert", {"alert_id": alert_id}, f,
                         lambda a: f"{a['rule_id']} {a['severity']}" if a else "no existe")

    def alerts_for_entity(self, entity: str, desde: str, hasta: str, exclude: str = "", limit: int = 15) -> list[dict]:
        def f():
            if is_hub(_ent(entity)):   # una entidad compartida por cientos no relaciona alertas
                return []
            return rows("""SELECT a.alert_id, a.created_at, a.rule_id, a.rule_name, a.severity
                FROM alert_entities e JOIN alerts a USING(alert_id)
                WHERE e.entity = ? AND a.created_at BETWEEN ? AND ? AND a.alert_id <> ?
                ORDER BY a.created_at LIMIT ?""", [_ent(entity), desde, hasta, exclude, limit])
        return self._run("alerts_for_entity", {"entity": entity, "desde": desde, "hasta": hasta}, f,
                         lambda r: f"{len(r)} alertas" + (f": {', '.join(sorted({x['rule_id'] for x in r}))}" if r else ""))

    # ------------------------------------------------------------ CMDB y directorio
    def get_asset(self, key: str) -> list[dict]:
        """Hostname, IP o rango tipo 'WEB-ECOM01..04' / 'POS-T*'. Incluye vulnerabilidades y servicio."""
        def f():
            k = key.strip()
            m = re.match(r"^(.*?)(\d+)\.\.(\d+)$", k)
            if m:
                cond, params = "upper(hostname) LIKE ?", [m.group(1).upper() + "%"]
            elif k.endswith("*"):
                cond, params = "upper(hostname) LIKE ?", [k[:-1].upper() + "%"]
            else:
                cond, params = "(upper(hostname) = ? OR ip = ?)", [k.upper(), k]
            assets = rows(f"SELECT * FROM activos WHERE {cond} LIMIT 10", params)
            for a in assets:
                a["vulnerabilities"] = rows("SELECT id, producto, severidad_cvss, estado, notas FROM vulnerabilidades WHERE hostname = ?", [a["hostname"]])
            return assets
        return self._run("get_asset", {"key": key}, f,
                         lambda r: "; ".join(f"{a['hostname']} criticidad {a['criticality']} ({a['zone']}, {a['business_service']})"
                                             + (f", {len(a['vulnerabilities'])} vulns" if a['vulnerabilities'] else "") for a in r)
                         or "no está en la CMDB (¿externo o no gestionado?)")

    def get_user(self, key: str) -> dict | None:
        def f():
            k = norm_user(key)
            r = rows("SELECT * FROM usuarios WHERE lower(username) = ? OR lower(upn) = ?", [k, (key or '').lower()])
            if not r:
                return None
            u = r[0]
            u["hr_events"] = rows("SELECT * FROM eventos_rrhh WHERE lower(usuario) = ?", [u["upn"].lower()])
            return u
        return self._run("get_user", {"key": key}, f,
                         lambda u: (f"{u['display_name']} · {u['title']} · tipo {u['account_type']} · priv {u['privileged']} · VIP {u['vip']}"
                                    + (f" · RRHH: {', '.join(h['tipo'] for h in u['hr_events'])}" if u['hr_events'] else "")) if u else "no encontrado")

    # ------------------------------------------------------------ logs
    def get_events(self, event_ids: list[str]) -> list[dict]:
        def f():
            out = []
            for eid in event_ids[:20]:
                src = PREFIX_SOURCE.get(eid.split("-")[0])
                if not src:
                    continue
                r = rows(f"SELECT to_json(t) AS raw FROM {src} t WHERE event_id = ?", [eid])
                if r:
                    out.append({"source": src, **r[0]["raw"]})
            return out
        return self._run("get_events", {"event_ids": event_ids[:20]}, f, lambda r: f"{len(r)}/{len(event_ids)} eventos encontrados")

    def entity_timeline(self, entity: str, desde: str, hasta: str, limit: int = 40, sources: list[str] | None = None) -> dict:
        """Qué hizo una entidad (usuario, host, IP, dominio, hash...) en la ventana. Devuelve recuentos y muestra."""
        def f():
            e = _ent(entity)
            src_cond = f"AND source IN ({','.join('?' * len(sources))})" if sources else ""
            params = [e, desde, hasta] + (sources or [])
            counts = rows(f"SELECT source, count(*) n FROM entity_events WHERE entity = ? AND ts BETWEEN ? AND ? {src_cond} GROUP BY 1 ORDER BY 2 DESC", params)
            idx = rows(f"SELECT DISTINCT source, event_id, ts FROM entity_events WHERE entity = ? AND ts BETWEEN ? AND ? {src_cond} ORDER BY ts LIMIT ?", params + [limit])
            events = []
            for i in idx:
                r = rows(f"SELECT to_json(t) AS raw FROM {i['source']} t WHERE event_id = ?", [i["event_id"]])
                if r:
                    events.append({"ts": i["ts"], "source": i["source"], "event_id": i["event_id"], "line": compact(r[0]["raw"])})
            out = {"entity": e, "counts": {c["source"]: c["n"] for c in counts}, "events": events,
                   "truncated": sum(c["n"] for c in counts) > len(events)}
            h = hubs().get(e)
            if h:   # avisamos al agente: compartir un hub no relaciona dos cosas
                out["hub"] = f"{h['kind']}: {h['reason']}"
            return out
        return self._run("entity_timeline", {"entity": entity, "desde": desde, "hasta": hasta}, f,
                         lambda r: (f"[{r['hub']}] " if r.get("hub") else "") +
                         (f"{sum(r['counts'].values())} eventos: " + ", ".join(f"{k} {v}" for k, v in r["counts"].items()) if r["counts"] else "sin actividad"))

    def search_logs(self, source: str, contains: str = "", desde: str = "", hasta: str = "", limit: int = 30) -> dict:
        """Búsqueda de texto en una fuente (como la API simulada, pero en milisegundos)."""
        def f():
            if source not in SOURCES:
                return {"error": f"fuente desconocida; usa una de {SOURCES}"}
            cond, params = ["1=1"], []
            if contains:
                cond.append("lower(CAST(to_json(t) AS VARCHAR)) LIKE ?"); params.append(f"%{contains.lower()}%")
            if desde:
                cond.append("ts >= ?"); params.append(desde)
            if hasta:
                cond.append("ts <= ?"); params.append(hasta)
            where = " AND ".join(cond)
            n = rows(f"SELECT count(*) n FROM {source} t WHERE {where}", params)[0]["n"]
            r = rows(f"SELECT to_json(t) AS raw FROM {source} t WHERE {where} ORDER BY ts LIMIT ?", params + [limit])
            return {"count": n, "events": [compact(x["raw"]) for x in r], "truncated": n > limit}
        return self._run("search_logs", {"source": source, "contains": contains, "desde": desde, "hasta": hasta}, f,
                         lambda r: r.get("error") or f"{r['count']} coincidencias")

    # ------------------------------------------------------------ inteligencia
    def intel(self, indicator: str) -> dict:
        """TIP interno + GeoIP/ASN + sandbox. 'sin coincidencias' NO significa limpio."""
        def f():
            ind = indicator.strip()
            tip = rows("SELECT * FROM ti_feed WHERE lower(value) = ?", [ind.lower()])
            geo = rows("SELECT * FROM geoip WHERE ip = ?", [ind])
            sbx = rows("SELECT raw FROM sandbox WHERE lower(sha256) = ?", [ind.lower()])
            return {"indicator": ind, "tip": tip[0] if tip else None, "geo": geo[0] if geo else None,
                    "sandbox": sbx[0]["raw"] if sbx else None}
        return self._run("intel", {"indicator": indicator}, f, _intel_summary)

    # ------------------------------------------------------------ cambios aprobados
    def matching_changes(self, entities: list[str], ts: str, alert_text: str = "") -> list[dict]:
        """Cambios y flujos aprobados vigentes en ts que mencionan alguna entidad (o rango de IP).
        Con alert_text, también encaja si un identificador del cambio (SCCM, NESSUS01, svc_sccm...) aparece en la alerta.
        Son CANDIDATOS: quien decide si cubren la actividad es el agente (y lo revisa la persona)."""
        def f():
            t = _iso(ts)
            out = []
            for c in rows("SELECT * FROM calendario_cambios"):
                ini, fin = _iso(c["inicio"].replace(" ", "T") + ":00+00:00"), _iso(c["fin"].replace(" ", "T") + ":00+00:00")
                # Ojo: el calendario está en hora local; damos 2 h de margen a cada lado
                if not (ini - timedelta(hours=2) <= t <= fin + timedelta(hours=2)):
                    continue
                text = " ".join(str(v) for v in c.values()).lower()
                hits = [e for e in entities if e and (e.lower() in text or _ip_in_text(e, text) or _range_hit(e, text))]
                if alert_text:
                    hits += [k for k in _change_tokens(c) if k.lower() in alert_text.lower()]
                if hits:
                    out.append({**c, "matched": sorted(set(hits))})
            return out
        return self._run("matching_changes", {"entities": entities, "ts": ts}, f,
                         lambda r: ", ".join(f"{c['id']} ({', '.join(c['matched'])})" for c in r) or "ningún cambio aprobado encaja")

    # ------------------------------------------------------------ comparación con lo habitual
    def baseline(self, question: str, entity: str, other: str = "", ts: str = "") -> dict:
        """¿Es la primera vez que…? question: user_origin(usuario, ip) · host_domain(equipo, dominio) ·
        prevalence(hash o fichero) · account_host(usuario, equipo) · user_hours(usuario) · key_origin(clave, ip)."""
        from core.baseline import QUESTIONS
        def f():
            fn = QUESTIONS.get(question)
            if not fn:
                return {"error": f"pregunta desconocida; usa una de {sorted(QUESTIONS)}"}
            t = ts or datetime.now(timezone.utc).isoformat()
            args = (entity, t) if question in ("prevalence", "user_hours") else (entity, other, t)
            return fn(*args).model_dump()
        return self._run("baseline", {"question": question, "entity": entity, "other": other, "ts": ts}, f,
                         lambda r: r.get("error") or (("⚠ " if r["attention"] else "") + r["answer"]))

    # ------------------------------------------------------------ despacho para el modo investigador
    def call(self, name: str, args: dict) -> Any:
        fn = getattr(self, name, None)
        if name not in TOOL_NAMES or fn is None:
            return {"error": f"herramienta desconocida: {name}"}
        try:
            return fn(**args)
        except TypeError as e:
            return {"error": f"argumentos inválidos: {e}"}


# ------------------------------------------------------------------ utilidades
def _ent(e: str) -> str:
    """Normaliza una entidad que llega del LLM o de la alerta para buscarla en entity_events."""
    e = e.strip()
    if "@" in e or "\\" in e or e.startswith(("adm.", "svc_", "ext.")):
        return norm_user(e) or e
    if re.match(r"^[A-Za-z]+(-[A-Za-z0-9]+)+$", e) and not re.search(r"\.", e):
        return e.upper()  # hostname
    return e.lower() if re.search(r"[a-z]", e) and "." in e and not re.match(r"^\d", e) else e


def _ip_in_text(ip: str, text: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)) and ip in text


def _range_hit(e: str, text: str) -> bool:
    """'192.0.2.11' dentro de '192.0.2.10-12'; 'WEB-ECOM03' dentro de 'WEB-ECOM01..04'."""
    for a, b, c in re.findall(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", text):
        try:
            ip = ipaddress.ip_address(e)
            if ipaddress.ip_address(a + b) <= ip <= ipaddress.ip_address(a + c):
                return True
        except ValueError:
            pass
    m = re.match(r"^([a-z\-]+?)(\d+)$", e.lower())
    if m:
        for pre, lo, hi in re.findall(r"([a-z\-]+?)(\d+)\.\.(\d+)", text):
            if pre == m.group(1) and int(lo) <= int(m.group(2)) <= int(hi):
                return True
    return False


_STOP = {"todas", "todos", "redes", "salvo", "correo", "puestos", "servidores", "directorio", "activo", "nuevo"}


def _change_tokens(c: dict) -> list[str]:
    """Identificadores con aspecto técnico de un cambio: NESSUS01, svc_sccm, SCCM, OT-MAINT-TEMP, asesoria@..."""
    text = f"{c['titulo']} {c['detalle']} {c['alcance']}"
    toks = re.findall(r"[A-Za-z0-9_.@\-]+", text)
    out = []
    for t in toks:
        t = t.strip(".-")
        if len(t) < 4 or t.lower() in _STOP or re.match(r"^\d", t):
            continue
        if re.search(r"[0-9_@]", t) or (t.isupper() and len(t) >= 4) or "." in t:
            out.append(t)
    return sorted(set(out))


def _intel_summary(r: dict) -> str:
    parts = []
    if r["tip"]:
        parts.append(f"TIP: {r['tip']['reputation']} ({r['tip'].get('malware_family') or r['tip'].get('tags')}, conf {r['tip']['confidence']})")
    if r["geo"]:
        g = r["geo"]
        flags = [k for k in ("is_tor", "is_vpn_provider", "is_hosting", "is_residential_proxy") if str(g.get(k)) == "True"]
        parts.append(f"{g['country']} {g['as_org']}" + (f" [{', '.join(flags)}]" if flags else ""))
    if r["sandbox"]:
        parts.append(f"sandbox: {r['sandbox']['verdict']} {r['sandbox'].get('malware_family', '')}")
    return " · ".join(parts) or "sin coincidencias (desconocido, no limpio)"


TOOL_NAMES = {"get_alert", "alerts_for_entity", "get_asset", "get_user", "get_events", "entity_timeline",
              "search_logs", "intel", "matching_changes", "baseline"}

TOOL_SPECS = [
    {"type": "function", "function": {"name": "get_asset", "description": "CMDB: criticidad, zona, servicio y vulnerabilidades de un host, IP o rango (WEB-ECOM01..04)",
     "parameters": {"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}}},
    {"type": "function", "function": {"name": "get_user", "description": "Directorio: rol, tipo de cuenta, privilegios, VIP y eventos de RRHH (viajes, bajas)",
     "parameters": {"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}}},
    {"type": "function", "function": {"name": "intel", "description": "TIP interno, GeoIP/ASN y sandbox de una IP, dominio o sha256",
     "parameters": {"type": "object", "properties": {"indicator": {"type": "string"}}, "required": ["indicator"]}}},
    {"type": "function", "function": {"name": "entity_timeline", "description": "Eventos de cualquier fuente de log de una entidad (usuario, host, IP, dominio, hash, cliente, clave cloud) entre dos fechas ISO",
     "parameters": {"type": "object", "properties": {"entity": {"type": "string"}, "desde": {"type": "string"}, "hasta": {"type": "string"},
                    "sources": {"type": "array", "items": {"type": "string"}}}, "required": ["entity", "desde", "hasta"]}}},
    {"type": "function", "function": {"name": "search_logs", "description": f"Búsqueda de texto en una fuente: {', '.join(SOURCES)}",
     "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "contains": {"type": "string"},
                    "desde": {"type": "string"}, "hasta": {"type": "string"}}, "required": ["source"]}}},
    {"type": "function", "function": {"name": "get_events", "description": "Eventos completos por event_id",
     "parameters": {"type": "object", "properties": {"event_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["event_ids"]}}},
    {"type": "function", "function": {"name": "alerts_for_entity", "description": "Otras alertas del SIEM de una entidad entre dos fechas",
     "parameters": {"type": "object", "properties": {"entity": {"type": "string"}, "desde": {"type": "string"}, "hasta": {"type": "string"}},
                    "required": ["entity", "desde", "hasta"]}}},
    {"type": "function", "function": {"name": "baseline", "description": "¿Es la primera vez que…? Compara con el historial previo a ts. "
     "question: user_origin (entity=usuario, other=ip) · host_domain (entity=equipo, other=dominio) · prevalence (entity=hash o fichero) · "
     "account_host (entity=usuario, other=equipo) · user_hours (entity=usuario) · key_origin (entity=clave AWS, other=ip)",
     "parameters": {"type": "object", "properties": {"question": {"type": "string", "enum": ["user_origin", "host_domain", "prevalence", "account_host", "user_hours", "key_origin"]},
                    "entity": {"type": "string"}, "other": {"type": "string"}, "ts": {"type": "string"}}, "required": ["question", "entity", "ts"]}}},
    {"type": "function", "function": {"name": "matching_changes", "description": "Cambios o flujos aprobados vigentes en una fecha que mencionan alguna de las entidades",
     "parameters": {"type": "object", "properties": {"entities": {"type": "array", "items": {"type": "string"}}, "ts": {"type": "string"}},
                    "required": ["entities", "ts"]}}},
]
