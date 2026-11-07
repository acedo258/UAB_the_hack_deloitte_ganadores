"""Recetas por runbook: las consultas concretas que haría un N1 en las "Comprobaciones" de cada RB.
Responsable: A (datos).

    from core.recipes import run_recipes
    checks = run_recipes(alert, by_type, tb)     # -> list[Check]

Cada Check responde a UNA comprobación del runbook con:
  - question:  la comprobación (p. ej. "RB-01.3 ¿Cuántos buzones lo recibieron?")
  - answer:    el hecho en una línea, calculado por código (recuentos, primera vez, etc.)
  - attention: True si el dato es anómalo según una regla simple y explícita (no decide nada: avisa)
  - events:    hasta N eventos de apoyo, con su event_id para que el agente pueda citarlos

Reglas de diseño:
  - Nada de logs crudos: recuentos + pocos eventos con las columnas útiles.
  - Una receta que falla no rompe el pack: queda una nota y se sigue.
  - Las recetas son genéricas por runbook; NUNCA conocen casos concretos del set de evaluación.
"""
from __future__ import annotations

import json
import re
import statistics
from datetime import datetime, timedelta
from typing import Any, Callable

from core.schemas import Check
from core.store import is_hub, norm_user, rows
from core.tools import ToolBox, _iso

MAX_EVENTS = 8
CUT = 180

H = timedelta(hours=1)
D = timedelta(days=1)

SUSPICIOUS_CMD = (r"vssadmin|shadowcopy|wbadmin|bcdedit|lsass|procdump|comsvcs|mimikatz|sekurlsa|psexec|"
                  r"-enc|encodedcommand|frombase64|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|"
                  r"net\s+group|net\s+user|nltest|whoami|anydesk|teamviewer|screenconnect|schtasks|reg\s+add")
COMPRESS_CMD = r"7z|7za|winrar|\brar\b|zip|compress-archive|tar\s|gpg|veracrypt|makecab"
PERSISTENCE_OPS = ("New-InboxRule", "Consent to application", "Add-MfaMethod", "Set-MailboxAutoReply")
CLOUD_SENSITIVE = r"^(GetCallerIdentity|List|Describe|Create|Attach|Put.*Policy|Delete(Trail|Bucket)|StopLogging|UpdateAssumeRole)"
SECRET_RE = r"(AWS_[A-Z_]+|NPM_TOKEN|GITHUB_TOKEN|[A-Z_]*SECRET[A-Z_]*)"
OT_PORTS = ("502", "44818")
OT_AUTHORIZED = {"ENG-WS01", "WMS01"}


# ------------------------------------------------------------------ utilidades
def iso(t: datetime) -> str:
    return t.isoformat()


def _cut(v: Any) -> Any:
    if isinstance(v, (dict, list)):
        v = {k: x for k, x in v.items() if x not in (None, "", [], {})} if isinstance(v, dict) else v
        v = json.dumps(v, ensure_ascii=False, default=str)
    if isinstance(v, str) and len(v) > CUT:
        return v[: CUT - 1] + "…"
    return v


def ev(r: dict, cols: list[str]) -> dict:
    """Evento compacto con solo las columnas útiles (siempre con event_id y ts si existen)."""
    out = {}
    for k in ["event_id", "ts", *cols]:
        v = r.get(k)
        if v not in (None, "", [], {}):
            out[k] = _cut(v)
    return out


def _in(values: list[str]) -> str:
    return ",".join("?" * len(values)) or "NULL"


class Ctx:
    """Lo que necesita una receta: la alerta, sus entidades por tipo y la caja de herramientas (para la traza)."""
    def __init__(self, a: dict, by_type: dict[str, list[str]], tb: ToolBox):
        self.a, self.by, self.tb = a, by_type, tb
        self.t = _iso(a["created_at"])
        self.ev = a.get("evidence") or {}
        self.checks: list[Check] = []

    def users(self) -> list[str]:
        # Fuera marcadores como "(161 cuentas)": no son usuarios reales
        return [u for u in self.by.get("user", []) if re.match(r"^[a-z0-9][a-z0-9._\-]*$", u)][:4]

    def hosts(self) -> list[str]:
        hs = list(self.by.get("host", []))
        for k in ("src", "dst", "from_host"):
            v = self.ev.get(k)
            if isinstance(v, str) and re.match(r"^[A-Z][A-Z0-9\-]+$", v) and v not in hs:
                hs.append(v)
        return hs[:3]

    def ext_ips(self, n: int = 50) -> list[str]:
        from core.context import is_internal
        return [i for i in self.by.get("ip", []) if not is_internal(i)][:n]

    def add(self, cid: str, question: str, fn: Callable[[], tuple[str, bool, list[dict], int | None]]) -> None:
        """Ejecuta una comprobación y la registra en la traza como recipe.<RB>.<id>."""
        def run():
            answer, attention, events, count = fn()
            return Check(id=cid, question=question, answer=answer, attention=attention,
                         count=count, events=events[:MAX_EVENTS])
        try:
            c = self.tb._run(f"recipe.{cid}", {"pregunta": question}, run,
                             lambda c: ("⚠ " if c.attention else "") + c.answer)
            self.checks.append(c)
        except Exception as e:  # una receta rota no tumba el pack
            self.checks.append(Check(id=cid, question=question, answer=f"no se pudo comprobar ({type(e).__name__}: {e})"[:200]))


# ------------------------------------------------------------------ RB-01 correo
def rb01(c: Ctx) -> None:
    mid = c.ev.get("message_id") or next(iter(c.by.get("message_id", [])), None)
    msgs = rows("SELECT * FROM email WHERE message_id = ? ORDER BY ts", [mid]) if mid else []
    sender = c.ev.get("sender") or (msgs[0]["sender"] if msgs else None)
    base_t = _iso(msgs[0]["ts"]) if msgs else c.t
    recipients = sorted({norm_user(r) for m in msgs for r in (m.get("recipients") or []) if norm_user(r)})

    def alcance():
        if not mid:
            return "la alerta no trae message_id", False, [], None
        n_by_sender = rows("SELECT count(*) n, count(DISTINCT message_id) m FROM email WHERE lower(sender) = lower(?) "
                           "AND ts BETWEEN ? AND ?", [sender, iso(c.t - 7 * D), iso(c.t + D)])[0] if sender else {"n": 0, "m": 0}
        evs = [ev(m, ["sender", "recipients", "subject", "verdict", "action", "spf", "dkim", "dmarc", "sender_ip"]) for m in msgs]
        return (f"{len(msgs)} entregas del mismo message_id a {len(recipients)} buzones; "
                f"el remitente envió {n_by_sender['n']} correos ({n_by_sender['m']} distintos) en ±7 días",
                len(recipients) >= 5, evs, len(recipients))
    c.add("RB-01.alcance", "RB-01.3 ¿Cuántos buzones lo recibieron? (message_id y remitente)", alcance)

    def remitente():
        if not sender:
            return "sin remitente", False, [], None
        dom = sender.split("@")[-1].lower()
        first = rows("SELECT min(ts) f, count(*) n FROM email WHERE lower(sender) = lower(?)", [sender])[0]
        dom_prev = rows("SELECT count(*) n FROM email WHERE lower(sender) LIKE ? AND ts < ?", [f"%@{dom}", iso(base_t)])[0]["n"]
        legit = c.ev.get("legit_supplier_domain")
        legit_n = rows("SELECT count(*) n FROM email WHERE lower(sender) LIKE ? AND ts < ?",
                       [f"%@{legit.lower()}", iso(base_t)])[0]["n"] if legit else None
        auth = msgs[0] if msgs else {}
        txt = (f"{sender}: visto por primera vez {first['f']} ({first['n']} correos en total); "
               f"{dom_prev} correos previos del dominio {dom}; SPF {auth.get('spf')}, DKIM {auth.get('dkim')}, DMARC {auth.get('dmarc')}")
        if legit:
            txt += f"; el proveedor legítimo ({legit}) tiene {legit_n} correos previos"
        bad_auth = any(str(auth.get(k, "")).lower() in ("fail", "softfail", "none") for k in ("spf", "dkim", "dmarc"))
        return txt, dom_prev == 0 or bad_auth or bool(legit and legit.lower() != dom), [], first["n"]
    c.add("RB-01.remitente", "RB-01.1 Remitente: antigüedad, suplantación y SPF/DKIM/DMARC", remitente)

    clicks = rows("SELECT * FROM email_clicks WHERE message_id = ? ORDER BY ts", [mid]) if mid else []

    def clics():
        evs = [ev(k, ["user", "url", "action", "verdict_at_click", "src_ip"]) for k in clicks]
        who = sorted({norm_user(k["user"]) for k in clicks})
        return (f"{len(clicks)} clics de {len(who)} usuarios" + (f": {', '.join(who[:5])}" if who else ""),
                bool(clicks), evs, len(clicks))
    c.add("RB-01.clics", "RB-01.4 ¿Hubo clic en el enlace? (email_clicks)", clics)

    def navegacion():
        out = []
        for k in clicks[:3]:
            kt = _iso(k["ts"])
            out += rows("""SELECT * FROM proxy WHERE norm_user("user") = ? AND ts BETWEEN ? AND ?
                           ORDER BY (method = 'POST') DESC, ts LIMIT 6""", [norm_user(k["user"]), iso(kt), iso(kt + 30 * timedelta(minutes=1))])
        posts = [p for p in out if p.get("method") == "POST"]
        evs = [ev(p, ["user", "method", "domain", "url", "action", "bytes_out", "category"]) for p in out]
        if not clicks:
            return "sin clics: no aplica", False, [], 0
        return (f"{len(out)} peticiones del proxy en los 30 min siguientes al clic; {len(posts)} POST"
                + (f" (a {', '.join(sorted({p['domain'] for p in posts}))})" if posts else ""), bool(posts), evs, len(out))
    c.add("RB-01.navegacion", "RB-01.4 ¿Qué navegó el usuario en los 30 min tras el clic? (proxy; POST = posible envío de credenciales)", navegacion)

    def ejecucion():
        names = sorted({x for m in msgs for x in _att_names(m)})
        if not names:
            return "el correo no tiene adjuntos", False, [], 0
        r = rows(f"""SELECT DISTINCT e.* FROM entity_events x JOIN edr_events e USING (event_id)
                     WHERE x.etype = 'file' AND x.source = 'edr_events' AND x.entity IN ({_in(names)}) AND x.ts >= ?
                     ORDER BY e.ts LIMIT 8""", names + [iso(base_t)])
        evs = [ev(e, ["hostname", "user", "parent_name", "process_name", "command_line", "event_type"]) for e in r]
        return (f"adjuntos {', '.join(names)}: " + (f"EJECUTADOS {len(r)} veces en {', '.join(sorted({e['hostname'] for e in r}))}"
                                                     if r else "sin ejecución en el EDR"), bool(r), evs, len(r))
    c.add("RB-01.ejecucion", "RB-01.4 ¿Se ejecutó algún adjunto? (edr_events, por nombre de fichero)", ejecucion)

    def logins():
        who = sorted({norm_user(k["user"]) for k in clicks}) or recipients[:5] or c.users()
        if not who:
            return "sin destinatarios", False, [], 0
        # Las IPs domésticas cambian: lo anómalo es un ASN o un país que el usuario no había usado nunca
        r = rows(f"""SELECT s.*, NOT EXISTS (SELECT 1 FROM idp_signins p WHERE norm_user(p.user_upn) = norm_user(s.user_upn)
                                                AND (p.asn = s.asn OR p.country = s.country) AND p.ts < ?) AS origen_nuevo
                     FROM idp_signins s WHERE norm_user(s.user_upn) IN ({_in(who)}) AND s.ts BETWEEN ? AND ?
                     ORDER BY origen_nuevo DESC, s.ts LIMIT 8""", [iso(base_t)] + who + [iso(base_t), iso(base_t + D)])
        new = [x for x in r if x["origen_nuevo"] and x["result"] == "success"]
        evs = [ev(x, ["user_upn", "result", "src_ip", "country", "asn", "mfa_result", "session_id", "origen_nuevo"]) for x in r]
        return (f"{len(r)} inicios de sesión en las 24 h siguientes; {len(new)} correctos desde un ASN y país que el usuario no había usado nunca",
                bool(new), evs, len(r))
    c.add("RB-01.logins", "RB-01.4 ¿Inicio de sesión anómalo del usuario después? (idp_signins, 24 h)", logins)


def _att_names(m: dict) -> list[str]:
    out = []
    for a in m.get("attachments") or []:
        if a.get("name"):
            out.append(a["name"].lower())
        for x in a.get("contains") or []:
            if x.get("name"):
                out.append(x["name"].lower())
    return out


# ------------------------------------------------------------------ RB-02 EDR
def rb02(c: Ctx) -> None:
    hosts = c.hosts()
    if not hosts:
        c.add("RB-02.host", "RB-02 Equipo afectado", lambda: ("la alerta no trae equipo", False, [], None))
        return
    h = hosts[0]

    def arbol():
        r = rows("""SELECT * FROM edr_events WHERE upper(hostname) = ? AND ts BETWEEN ? AND ?
                    ORDER BY abs(epoch(ts) - epoch(CAST(? AS TIMESTAMPTZ))) LIMIT 14""",
                 [h, iso(c.t - 2 * H), iso(c.t + 2 * H), iso(c.t)])
        r.sort(key=lambda x: x["ts"])
        total = rows("SELECT count(*) n FROM edr_events WHERE upper(hostname) = ? AND ts BETWEEN ? AND ?",
                     [h, iso(c.t - 2 * H), iso(c.t + 2 * H)])[0]["n"]
        evs = [ev(e, ["event_type", "user", "parent_name", "process_name", "command_line", "signer", "integrity"]) for e in r]
        return f"{total} eventos del EDR en {h} en ±2 h (se muestran los {len(r)} más cercanos a la alerta)", False, evs, total
    c.add("RB-02.arbol", f"RB-02.1 Árbol de procesos de {h} en ±2 h", arbol)

    def post():
        r = rows(f"""SELECT * FROM edr_events WHERE upper(hostname) = ? AND ts BETWEEN ? AND ?
                     AND (event_type <> 'process_start' OR regexp_matches(lower(command_line), ?))
                     ORDER BY ts LIMIT 10""", [h, iso(c.t - D), iso(c.t + D), SUSPICIOUS_CMD])
        kinds: dict[str, int] = {}
        for e in r:
            kinds[e["event_type"]] = kinds.get(e["event_type"], 0) + 1
        evs = [ev(e, ["event_type", "user", "parent_name", "process_name", "command_line", "details"]) for e in r]
        flag = any(e["event_type"] in ("process_access", "registry_set", "service_install") for e in r) or \
            any(re.search(r"vssadmin|shadowcopy|lsass|psexec|mimikatz", (e.get("command_line") or "").lower()) for e in r)
        return ("persistencia/credenciales/herramientas en ±24 h: " + (", ".join(f"{k} {v}" for k, v in kinds.items()) or "nada"),
                flag, evs, len(r))
    c.add("RB-02.post", f"RB-02.4 Persistencia, LSASS, borrado de copias o herramientas de ataque en {h} (±24 h)", post)

    def red():
        r = rows("""WITH d AS (SELECT lower(domain) d, count(*) n, min(ts) primero FROM proxy
                               WHERE upper(hostname) = ? AND ts BETWEEN ? AND ? GROUP BY 1)
                    SELECT d.d AS domain, d.n, d.primero,
                           (SELECT count(DISTINCT p.hostname) FROM proxy p WHERE lower(p.domain) = d.d) AS equipos
                    FROM d ORDER BY equipos, n DESC LIMIT 8""", [h, iso(c.t), iso(c.t + D)])
        rare = [x for x in r if x["equipos"] <= 2]
        return (f"tras la alerta {h} contactó {len(r)}+ dominios; {len(rare)} raros (≤2 equipos en toda la red)"
                + (f": {', '.join(x['domain'] for x in rare)}" if rare else ""), bool(rare),
                [{"domain": x["domain"], "peticiones": x["n"], "primera": x["primero"], "equipos_en_la_red": x["equipos"]} for x in r], len(r))
    c.add("RB-02.red", f"RB-02.4 Red tras la alerta: dominios que contacta {h} y cuántos equipos más los ven", red)

    def cuentas():
        ad = rows("""SELECT norm_user(subject) cuenta, norm_user(target) destino, event, count(*) n, min(ts) primero
                     FROM ad_events WHERE upper(src_host) = ? AND ts BETWEEN ? AND ? GROUP BY ALL ORDER BY primero LIMIT 8""",
                  [h, iso(c.t - D), iso(c.t + D)])
        edr_users = [x["u"] for x in rows("""SELECT DISTINCT norm_user("user") u FROM edr_events WHERE upper(hostname) = ?
                                             AND ts BETWEEN ? AND ? AND "user" IS NOT NULL""", [h, iso(c.t - D), iso(c.t + D)]) if x["u"]]
        priv = [u for u in edr_users + [x["cuenta"] for x in ad] if u and u.startswith("adm.")]
        flag = bool(priv) and h != "JUMP01"
        return (f"cuentas activas en {h} (±24 h): {', '.join(sorted(set(edr_users))) or 'ninguna en EDR'}; {len(ad)} eventos de AD desde el equipo"
                + (f"; cuentas adm.* fuera de JUMP01: {', '.join(sorted(set(priv)))}" if flag else ""), flag, ad, len(ad))
    c.add("RB-02.cuentas", f"RB-02.5 ¿Qué cuentas se usaron en {h} y contra qué? (EDR + AD)", cuentas)


# ------------------------------------------------------------------ RB-03 identidad
def rb03(c: Ctx) -> None:
    users = c.users()
    u = users[0] if users else None
    sid = c.ev.get("session_id") or next(iter(c.by.get("session", [])), None)
    ips = c.ext_ips(20)

    if ips and (not u or c.ev.get("distinct_accounts")):
        def spraying():
            # Ataque contra muchas cuentas: lo que importa es si ALGUNA entró y qué hizo después
            fails = rows(f"""SELECT count(*) n, count(DISTINCT u) cuentas FROM (
                               SELECT norm_user("user") u FROM vpn WHERE src_ip IN ({_in(ips)}) AND action <> 'connect' AND ts BETWEEN ? AND ?
                               UNION ALL SELECT norm_user(user_upn) FROM idp_signins WHERE src_ip IN ({_in(ips)}) AND result <> 'success' AND ts BETWEEN ? AND ?)""",
                         ips + [iso(c.t - D), iso(c.t + D)] + ips + [iso(c.t - D), iso(c.t + D)])[0]
            ok = rows(f"""SELECT 'vpn' fuente, event_id, ts, norm_user("user") cuenta, src_ip, assigned_ip, bytes, mfa_result FROM vpn
                          WHERE src_ip IN ({_in(ips)}) AND action = 'connect' AND ts BETWEEN ? AND ?
                          UNION ALL SELECT 'idp_signins', event_id, ts, norm_user(user_upn), src_ip, NULL, NULL, mfa_result FROM idp_signins
                          WHERE src_ip IN ({_in(ips)}) AND result = 'success' AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 8""",
                      ips + [iso(c.t - D), iso(c.t + D)] + ips + [iso(c.t - D), iso(c.t + D)])
            return (f"desde {len(ips)} IPs: {fails['n']} intentos fallidos contra {fails['cuentas']} cuentas; "
                    + (f"{len(ok)} accesos CORRECTOS: {', '.join(sorted({x['cuenta'] for x in ok}))}" if ok else "ningún acceso correcto"),
                    bool(ok), ok, len(ok))
        c.add("RB-03.spraying", "RB-03 Ataque a muchas cuentas: ¿alguna llegó a entrar desde esas IPs?", spraying)

    def sesion():
        if sid:
            r = rows("SELECT * FROM idp_signins WHERE session_id = ? ORDER BY ts LIMIT 10", [sid])
            what = f"sesión {sid}"
        elif u:
            r = rows("SELECT * FROM idp_signins WHERE norm_user(user_upn) = ? AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 10",
                     [u, iso(c.t - 2 * H), iso(c.t + 2 * H)])
            what = f"inicios de sesión de {u} en ±2 h"
        else:
            return "sin usuario ni sesión", False, [], None
        evs = [ev(x, ["user_upn", "app", "result", "failure_reason", "mfa_method", "mfa_result", "src_ip", "country", "asn",
                      "user_agent", "device_id", "device_compliant", "risk_level"]) for x in r]
        ips = sorted({x["src_ip"] for x in r if x.get("src_ip")})
        devs = sorted({str(x.get("device_id")) for x in r})
        # Solo contexto: si el origen es anómalo lo juzga BL.user_origin (país, ASN común, origen ya alertado)
        return f"{what}: {len(r)} eventos, IPs {', '.join(ips) or '-'}, dispositivos {', '.join(devs)}", False, evs, len(r)
    c.add("RB-03.sesion", "RB-03.1-2 La sesión completa: origen, dispositivo y user agent", sesion)

    if not u:
        return

    def mfa():
        r = rows("""SELECT mfa_result, count(*) n FROM idp_signins WHERE norm_user(user_upn) = ? AND ts BETWEEN ? AND ?
                    GROUP BY 1 ORDER BY 2 DESC""", [u, iso(c.t - 2 * H), iso(c.t + 2 * H)])
        d = {x["mfa_result"]: x["n"] for x in r}
        fails = d.get("denied", 0) + d.get("timeout", 0)
        return (f"MFA de {u} en ±2 h: " + (", ".join(f"{k} {v}" for k, v in d.items()) or "sin eventos"),
                fails >= 3 and d.get("approved", 0) > 0, [], fails)
    c.add("RB-03.mfa", "RB-03.3 Secuencia de MFA (muchos denied/timeout y luego approved = fatiga MFA)", mfa)

    # RB-03.1 "¿origen conocido?" lo responde BL.user_origin (core/baseline.py), con país, ASN común y origen ya alertado

    def despues():
        r = rows("""SELECT * FROM idp_audit WHERE (norm_user(actor_upn) = ? OR norm_user(target) = ?) AND ts BETWEEN ? AND ?
                    ORDER BY (operation IN ('New-InboxRule','Consent to application','Add-MfaMethod','Set-MailboxAutoReply')) DESC, ts LIMIT 8""",
                 [u, u, iso(c.t - H), iso(c.t + 2 * D)])
        pers = sorted({x["operation"] for x in r if x["operation"] in PERSISTENCE_OPS})
        evs = [ev(x, ["actor_upn", "operation", "target", "src_ip", "details"]) for x in r]
        return (f"{len(r)} operaciones en idp_audit en las 48 h siguientes" + (f"; persistencia: {', '.join(pers)}" if pers else ""),
                bool(pers), evs, len(r))
    c.add("RB-03.despues", "RB-03.5 ¿Qué hizo la sesión después? (reglas de buzón, OAuth, MFA nuevo, descargas)", despues)

    def vpn():
        r = rows("""SELECT src_ip, country, action, mfa_result, count(*) n, min(ts) primero FROM vpn
                    WHERE norm_user("user") = ? AND ts BETWEEN ? AND ? GROUP BY ALL ORDER BY primero LIMIT 8""",
                 [u, iso(c.t - D), iso(c.t + D)])
        return f"{sum(x['n'] for x in r)} eventos de VPN de {u} en ±24 h desde {len({x['src_ip'] for x in r})} IPs", False, r, len(r)
    c.add("RB-03.vpn", "RB-03 Conexiones VPN del usuario (±24 h)", vpn)


# ------------------------------------------------------------------ RB-04 DLP
def rb04(c: Ctx) -> None:
    users = c.users()
    if not users:
        return
    u = users[0]

    def envios():
        r = rows("""SELECT * FROM dlp WHERE norm_user("user") = ? AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 10""",
                 [u, iso(c.t - 7 * D), iso(c.t + D)])
        dests = sorted({x["destination"] for x in r if x.get("destination")})
        evs = [ev(x, ["channel", "destination", "file_name", "file_size", "policy", "matches", "action"]) for x in r]
        return f"{len(r)} eventos DLP de {u} en -7/+1 días hacia {len(dests)} destinos: {', '.join(dests[:6])}", len(dests) > 2, evs, len(r)
    c.add("RB-04.envios", "RB-04.1-2 Qué datos y a qué destinos ha enviado el usuario (DLP, 7 días)", envios)

    def sql():
        r = rows("""SELECT object, statement_type, count(*) consultas, sum(rows_returned) filas, min(ts) primera
                    FROM sql_audit WHERE norm_user("user") = ? AND ts BETWEEN ? AND ? GROUP BY ALL ORDER BY filas DESC LIMIT 6""",
                 [u, iso(c.t - 3 * D), iso(c.t + H)])
        filas = sum(x["filas"] or 0 for x in r)
        return f"{filas} filas devueltas en {sum(x['consultas'] for x in r)} consultas SQL en las 72 h previas", filas > 1000, r, filas
    c.add("RB-04.sql", "RB-04.4 ¿Hubo consultas masivas antes? (sql_audit, 72 h)", sql)

    def comprimir():
        r = rows("""SELECT * FROM edr_events WHERE (norm_user("user") = ? OR upper(hostname) IN (SELECT upper(hostname) FROM dlp
                    WHERE norm_user("user") = ?)) AND ts BETWEEN ? AND ? AND regexp_matches(lower(command_line), ?)
                    ORDER BY ts LIMIT 6""", [u, u, iso(c.t - 3 * D), iso(c.t + H), COMPRESS_CMD])
        evs = [ev(x, ["hostname", "process_name", "command_line"]) for x in r]
        return f"{len(r)} ejecuciones de compresión o cifrado en las 72 h previas", bool(r), evs, len(r)
    c.add("RB-04.comprimir", "RB-04.4 ¿Comprimió o cifró ficheros antes? (EDR, 72 h)", comprimir)

    def correo_ext():
        r = rows("""SELECT * FROM email WHERE norm_user(sender) = ? AND ts BETWEEN ? AND ?
                    AND len(list_filter(recipients, lambda x: lower(x) NOT LIKE '%@tarvia.example')) > 0 ORDER BY ts LIMIT 8""",
                 [u, iso(c.t - 7 * D), iso(c.t + D)])
        evs = [{**ev(x, ["recipients", "subject"]), "adjuntos": _att_names(x)} for x in r]
        personal = [x for x in r if any(re.search(r"gmail|hotmail|outlook|yahoo|personal|icloud|proton", y.lower())
                                        for y in x.get("recipients") or [])]
        return (f"{len(r)} correos a direcciones externas en -7/+1 días; {len(personal)} a buzones que parecen personales",
                bool(personal), evs, len(r))
    c.add("RB-04.correo", "RB-04.2 ¿Envió correo a direcciones externas o personales? (7 días)", correo_ext)


# ------------------------------------------------------------------ RB-05 tienda online
def rb05(c: Ctx) -> None:
    ips = c.ext_ips(50)
    custs = c.by.get("customer", [])[:20]
    win = (iso(c.t - D), iso(c.t + D))
    success: list[dict] = []

    if ips:
        def logins():
            nonlocal success
            r = rows(f"""SELECT result, count(*) n, count(DISTINCT customer_id) clientes FROM ecom_auth
                         WHERE src_ip IN ({_in(ips)}) AND ts BETWEEN ? AND ? GROUP BY 1""", ips + list(win))
            success = rows(f"""SELECT customer_id, min(ts) ts, any_value(src_ip) src_ip, any_value(device_fp) device_fp
                              FROM ecom_auth WHERE src_ip IN ({_in(ips)}) AND result = 'success' AND ts BETWEEN ? AND ?
                              GROUP BY 1 ORDER BY 2 LIMIT 20""", ips + list(win))
            d = {x["result"]: x for x in r}
            ok = d.get("success", {}).get("n", 0)
            return (f"desde las {len(ips)} IPs: {d.get('failure', {}).get('n', 0)} fallos y {ok} accesos correctos a "
                    f"{len(success)} cuentas en ±24 h", ok > 0, success, ok)
        c.add("RB-05.logins", "RB-05.2 ¿Cuántos accesos CORRECTOS hubo desde esas IPs? (ecom_auth)", logins)

        def waf():
            r = rows(f"""SELECT action, count(*) n, count(DISTINCT uri) rutas, any_value(rule_msg) ejemplo FROM waf
                         WHERE src_ip IN ({_in(ips)}) AND ts BETWEEN ? AND ? GROUP BY 1""", ips + list(win))
            allowed = sum(x["n"] for x in r if str(x["action"]).lower() not in ("block", "blocked", "deny"))
            return ("WAF desde esas IPs: " + (", ".join(f"{x['action']} {x['n']}" for x in r) or "sin eventos"),
                    allowed > 0 and any(str(x["action"]).lower() in ("block", "blocked") for x in r), r, allowed)
        c.add("RB-05.waf", "RB-05.1 ¿El WAF bloqueó todo o pasó algo?", waf)

    def cambios():
        ids = sorted({s["customer_id"] for s in success} | set(custs))
        if not ids:
            return "sin cuentas a revisar", False, [], 0
        r = rows(f"""SELECT * FROM ecom_account WHERE customer_id IN ({_in(ids)}) AND ts BETWEEN ? AND ?
                     AND event <> 'order_created' ORDER BY ts LIMIT 10""", ids + [iso(c.t - D), iso(c.t + 2 * D)])
        risky = [x for x in r if x["event"] in ("email_change", "giftcard_purchase")]
        evs = [ev(x, ["customer_id", "event", "details", "amount", "src_ip"]) for x in r]
        return (f"{len(r)} cambios de cuenta en {len(ids)} cuentas; {len(risky)} cambios de email o compras de tarjeta regalo",
                bool(risky), evs, len(r))
    c.add("RB-05.cambios", "RB-05.3 Tras el acceso: ¿cambio de email/dirección o tarjeta regalo? (ecom_account, 48 h)", cambios)

    hosts = c.hosts()
    if hosts:
        def shell():
            r = rows(f"""SELECT * FROM edr_events WHERE upper(hostname) IN ({_in(hosts)}) AND ts BETWEEN ? AND ?
                         AND regexp_matches(lower(parent_name), 'w3wp|httpd|nginx|php|java|tomcat|node')
                         ORDER BY ts LIMIT 8""", hosts + [iso(c.t - D), iso(c.t + D)])
            evs = [ev(x, ["hostname", "parent_name", "process_name", "command_line"]) for x in r]
            return f"{len(r)} procesos lanzados por el servidor web en ±24 h", bool(r), evs, len(r)
        c.add("RB-05.shell", "RB-05.4 ¿El servidor web lanzó una shell? ¿Qué leyó?", shell)


# ------------------------------------------------------------------ RB-06 cloud
def rb06(c: Ctx) -> None:
    keys = c.by.get("access_key", [])[:2]
    cloud = (c.a.get("entities") or {}).get("cloud") or {}
    ident = norm_user(cloud.get("identity")) if cloud.get("identity") else None
    cond, params = [], []
    if keys:
        cond.append(f"userIdentity.accessKeyId IN ({_in(keys)})"); params += keys
    if ident:
        cond.append("norm_user(userIdentity.userName) = ?"); params.append(ident)
    if not cond:
        c.add("RB-06.id", "RB-06 Identidad cloud", lambda: ("la alerta no trae clave ni identidad", False, [], None))
        return
    who = " OR ".join(cond)

    def historial():
        r = rows(f"""SELECT sourceIPAddress ip, left(userAgent, 60) ua, count(*) n, min(ts) primero, max(ts) ultimo
                     FROM cloudtrail WHERE {who} GROUP BY ALL ORDER BY primero LIMIT 8""", params)
        new = [x for x in r if abs((_iso(x["primero"]) - c.t).total_seconds()) < 6 * 3600]
        return (f"{len(r)} combinaciones IP/user agent en todo el historial; {len(new)} aparecen por primera vez cerca de la alerta"
                + (f": {', '.join(x['ip'] for x in new)}" if new else "")
                + (" (la clave no tiene historial anterior)" if new and len(r) == len(new) else ""), bool(new), r, len(r))
    c.add("RB-06.historial", "RB-06.1-2 ¿Desde dónde se usa normalmente esta clave o identidad?", historial)

    def persistencia():
        r = rows(f"""SELECT * FROM cloudtrail WHERE ({who}) AND ts BETWEEN ? AND ? AND regexp_matches(eventName, ?)
                     ORDER BY ts LIMIT 10""", params + [iso(c.t - 2 * D), iso(c.t + 2 * D), CLOUD_SENSITIVE])
        created = sorted({(x.get("requestParameters") or {}).get("userName") for x in r} - {None})
        evs = [ev(x, ["eventName", "sourceIPAddress", "requestParameters", "errorCode"]) for x in r]
        pers = [x for x in r if re.match(r"^(Create|Attach|Put)", x["eventName"])]
        return (f"{len(r)} llamadas de reconocimiento o cambios en ±48 h; {len(pers)} de persistencia"
                + (f"; usuarios afectados: {', '.join(created)}" if created else ""), bool(pers), evs, len(r))
    c.add("RB-06.persistencia", "RB-06.2-3 Reconocimiento (GetCallerIdentity, List*) y persistencia (usuarios, claves, políticas)", persistencia)

    def origen():
        names = [n for n in [ident] if n]
        r = rows(f"""SELECT * FROM cloudtrail WHERE eventName IN ('CreateUser', 'CreateAccessKey', 'AttachUserPolicy', 'PutUserPolicy')
                     AND norm_user(requestParameters.userName) IN ({_in(names)}) ORDER BY ts LIMIT 6""", names) if names else []
        creators = sorted({norm_user((x.get("userIdentity") or {}).get("userName")) for x in r} - {None})
        evs = [ev(x, ["eventName", "userIdentity", "sourceIPAddress", "requestParameters"]) for x in r]
        if not names:
            return "la alerta no trae identidad", False, [], None
        return ((f"{ident} fue creada o modificada por {', '.join(creators)} ({len(r)} eventos)" if r
                 else f"no hay registro de quién creó {ident} (identidad anterior al periodo de logs)"),
                any(_iso(x["ts"]) > c.t - 30 * D for x in r), evs, len(r))
    c.add("RB-06.origen", "RB-06.3 ¿Quién creó esta identidad o su clave, y cuándo?", origen)

    def datos():
        new_users = [x["u"] for x in rows(f"""SELECT DISTINCT norm_user(requestParameters.userName) u FROM cloudtrail
                       WHERE ({who}) AND eventName = 'CreateUser' AND ts BETWEEN ? AND ?""", params + [iso(c.t - 2 * D), iso(c.t + 2 * D)])]
        w2 = who + (f" OR norm_user(userIdentity.userName) IN ({_in(new_users)})" if new_users else "")
        r = rows(f"""SELECT requestParameters.bucketName bucket, norm_user(userIdentity.userName) identidad, count(*) n,
                            sum(bytes_transferred) bytes, min(ts) primero FROM cloudtrail
                     WHERE ({w2}) AND eventName = 'GetObject' AND ts BETWEEN ? AND ? GROUP BY ALL ORDER BY bytes DESC LIMIT 6""",
                 params + new_users + [iso(c.t - D), iso(c.t + 3 * D)])
        total = sum(x["bytes"] or 0 for x in r)
        return (f"{sum(x['n'] for x in r)} GetObject, {total / 1e9:.1f} GB" + (f" (incluye usuarios creados: {', '.join(new_users)})" if new_users else ""),
                total > 1e9, r, sum(x["n"] for x in r))
    c.add("RB-06.datos", "RB-06.4 Volumen de datos descargados (GetObject), también por los usuarios recién creados", datos)


# ------------------------------------------------------------------ RB-07 Vela
def rb07(c: Ctx) -> None:
    custs = c.by.get("customer", [])[:3]
    ips = c.by.get("ip", [])[:3]
    sid = next(iter(c.by.get("session", [])), None)
    if not (custs or ips or sid):
        return

    def conversacion():
        if sid:
            r = rows("SELECT * FROM ai_gateway WHERE session_id = ? ORDER BY ts", [sid])
        else:
            r = rows(f"""SELECT * FROM ai_gateway WHERE (customer_id IN ({_in(custs)}) OR src_ip IN ({_in(ips)}))
                         AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 10""", custs + ips + [iso(c.t - H), iso(c.t + H)])
        foreign = []
        for x in r:
            own = x.get("customer_id")
            for tcall in x.get("tool_calls") or []:
                other = (tcall.get("args") or {}).get("customer_id")
                if other and other != own:
                    foreign.append(f"{tcall['name']}({other}) en sesión de {own}")
        evs = [{**ev(x, ["session_id", "customer_id", "authenticated", "src_ip", "prompt", "response_summary"]),
                "tools": [f"{t.get('name')}({(t.get('args') or {}).get('customer_id') or ''})={t.get('result')}" for t in x.get("tool_calls") or []],
                "guardrail": _cut(x.get("guardrail"))} for x in r]
        return (f"{len(r)} mensajes de la conversación en ±1 h; "
                + (f"herramientas con datos de OTRO cliente: {'; '.join(foreign[:4])}" if foreign else "ninguna herramienta usa datos de otro cliente"),
                bool(foreign), evs, len(r))
    c.add("RB-07.conversacion", "RB-07.1-3 Conversación completa y llamadas a herramientas (¿con el id de otro cliente?)", conversacion)

    def otras():
        r = rows(f"""SELECT src_ip, count(DISTINCT session_id) sesiones, count(DISTINCT customer_id) clientes,
                            count(*) FILTER (WHERE guardrail.triggered) guardarrail
                     FROM ai_gateway WHERE (src_ip IN ({_in(ips)}) OR customer_id IN ({_in(custs)})) AND ts BETWEEN ? AND ?
                     GROUP BY 1 ORDER BY 2 DESC LIMIT 6""", ips + custs + [iso(c.t - 7 * D), iso(c.t + 7 * D)])
        many = [x for x in r if x["clientes"] > 2]
        return (f"{sum(x['sesiones'] for x in r)} sesiones de las mismas IPs o clientes en ±7 días"
                + (f"; IPs con más de 2 clientes distintos: {', '.join(x['src_ip'] for x in many)}" if many else ""), bool(many), r, len(r))
    c.add("RB-07.otras", "RB-07.4 ¿La misma IP o cliente aparece en otras sesiones?", otras)


# ------------------------------------------------------------------ RB-08 OT
def rb08(c: Ctx) -> None:
    src = c.ev.get("src") or next(iter(c.hosts()), None)
    if not src:
        return
    asset = rows("SELECT hostname, ip, zone FROM activos WHERE upper(hostname) = upper(?) OR ip = ?", [src, src])
    ip = asset[0]["ip"] if asset else src
    host = asset[0]["hostname"].upper() if asset else src.upper()

    def trafico():
        r = rows(f"""SELECT dst_ip, dst_port, action, zone_dst, count(*) n, min(ts) primero FROM firewall
                     WHERE src_ip = ? AND ts BETWEEN ? AND ? AND (zone_dst = 'LOGISTICS-OT' OR dst_port IN ({_in(list(OT_PORTS))}))
                     GROUP BY ALL ORDER BY primero LIMIT 8""", [ip, iso(c.t - D), iso(c.t + D)] + list(OT_PORTS))
        ok = host in OT_AUTHORIZED
        return (f"origen {host} ({ip}) {'AUTORIZADO' if ok else 'NO está entre los autorizados (ENG-WS01, WMS01)'}; "
                f"{sum(x['n'] for x in r)} conexiones hacia OT en ±24 h", not ok, r, len(r))
    c.add("RB-08.trafico", "RB-08.1-2 ¿Origen autorizado? Tráfico hacia OT (Modbus 502, EtherNet/IP 44818)", trafico)

    def previa():
        r = rows("""SELECT * FROM edr_events WHERE upper(hostname) = ? AND ts BETWEEN ? AND ?
                    AND (event_type <> 'process_start' OR regexp_matches(lower(command_line), ?)) ORDER BY ts LIMIT 8""",
                 [host, iso(c.t - D), iso(c.t + H), SUSPICIOUS_CMD])
        evs = [ev(x, ["event_type", "user", "process_name", "command_line"]) for x in r]
        return f"{len(r)} eventos sospechosos en {host} en las 24 h previas", bool(r), evs, len(r)
    c.add("RB-08.previa", "RB-08.3 ¿Actividad sospechosa previa en el equipo de origen?", previa)


# ------------------------------------------------------------------ RB-09 red
def rb09(c: Ctx) -> None:
    domains = [d for d in c.by.get("domain", []) if not d.endswith("tarvia.example")][:2]
    if c.ev.get("domain") and c.ev["domain"].lower() not in domains:
        domains.insert(0, c.ev["domain"].lower())
    hosts = c.hosts()

    for d in domains[:2]:
        def alcance(d=d):
            r = rows("""SELECT count(DISTINCT hostname) equipos, min(ts) primero, count(*) n FROM (
                          SELECT upper(hostname) hostname, ts FROM proxy WHERE lower(domain) = ? UNION ALL
                          SELECT upper(hostname), ts FROM dns WHERE lower(query) = ? OR lower(query) LIKE ?)""", [d, d, f"%.{d}"])[0]
            top = rows("""SELECT upper(hostname) hostname, count(*) n FROM proxy WHERE lower(domain) = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 5""", [d])
            return (f"{d}: {r['equipos']} equipos lo contactan, {r['n']} peticiones, visto por primera vez {r['primero']}",
                    0 < (r["equipos"] or 0) <= 3, top, r["equipos"])
        c.add(f"RB-09.alcance.{d}", f"RB-09.1 ¿Cuántos equipos contactan {d} y desde cuándo?", alcance)

        def beacon(d=d):
            h = hosts[0] if hosts else (rows("SELECT upper(hostname) h FROM proxy WHERE lower(domain) = ? GROUP BY 1 ORDER BY count(*) DESC LIMIT 1", [d]) or [{"h": None}])[0]["h"]
            if not h:
                return "ningún equipo interno en el proxy", False, [], None
            ts = [_iso(x["ts"]) for x in rows("""SELECT ts FROM proxy WHERE lower(domain) = ? AND upper(hostname) = ?
                                                  AND ts BETWEEN ? AND ? ORDER BY ts""", [d, h, iso(c.t - D), iso(c.t + D)])]
            via = "proxy"
            if len(ts) < 5:   # sin proxy: probamos con DNS, pero en DNS la periodicidad es normal (resolvers, listas antispam)
                via = "DNS"
                ts = [_iso(x["ts"]) for x in rows("""SELECT ts FROM dns WHERE (lower(query) = ? OR lower(query) LIKE ?)
                          AND upper(hostname) = ? AND ts BETWEEN ? AND ? ORDER BY ts""", [d, f"%.{d}", h, iso(c.t - D), iso(c.t + D)])]
            gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
            if len(gaps) < 4:
                return f"{h} → {d}: {len(ts)} conexiones en ±24 h, pocas para medir periodicidad", False, [], len(ts)
            mean, sd = statistics.mean(gaps), statistics.pstdev(gaps)
            cv = sd / mean if mean else 0
            periodic = cv < 0.25
            return (f"{h} → {d} ({via}): {len(ts)} conexiones, intervalo medio {mean:.0f} s, variación {cv:.0%}"
                    + (" → periódico, típico de beaconing" if periodic and via == "proxy" else "")
                    + (" → periódico, pero en DNS eso es normal; ver RB-09.tunel" if periodic and via == "DNS" else ""),
                    periodic and via == "proxy" and not is_hub(d),
                    [{"host": h, "conexiones": len(ts), "intervalo_medio_s": round(mean), "desviacion_s": round(sd)}], len(ts))
        c.add(f"RB-09.beacon.{d}", f"RB-09.1 Beaconing hacia {d}: intervalo y varianza", beacon)

        def tunel(d=d):
            # Túnel DNS: muchos subdominios distintos y largos (datos codificados en la etiqueta), no periodicidad
            r = rows("""SELECT count(*) n, count(DISTINCT lower(query)) distintas,
                               avg(length(split_part(lower(query), '.', 1))) etiqueta_media,
                               count(*) FILTER (WHERE qtype = 'TXT') txt, count(DISTINCT upper(hostname)) equipos
                        FROM dns WHERE lower(query) LIKE ? AND ts BETWEEN ? AND ?""", [f"%.{d}", iso(c.t - D), iso(c.t + D)])[0]
            if not r["n"]:
                return f"{d}: sin consultas DNS a subdominios en ±24 h", False, [], 0
            lab = r["etiqueta_media"] or 0
            sus = r["distintas"] >= 50 and lab >= 20
            return (f"{d}: {r['n']} consultas a {r['distintas']} subdominios distintos, etiqueta media {lab:.0f} caracteres, "
                    f"{r['txt']} de tipo TXT, desde {r['equipos']} equipo(s)" + (" → patrón de túnel DNS" if sus else ""),
                    sus, [r], r["distintas"])
        c.add(f"RB-09.tunel.{d}", f"RB-09.1 ¿Túnel DNS hacia {d}? (subdominios distintos y su longitud)", tunel)

    acct = next((u for u in c.users() if u.startswith(("adm.", "svc_"))), None) or norm_user(c.ev.get("account") or "")
    if acct:
        def lateral():
            r = rows("""SELECT upper(src_host) origen, norm_user(target) destino, event, count(*) n, min(ts) primero
                        FROM ad_events WHERE norm_user(subject) = ? AND ts BETWEEN ? AND ? GROUP BY ALL ORDER BY primero LIMIT 8""",
                     [acct, iso(c.t - D), iso(c.t + D)])
            origins = sorted({x["origen"] for x in r if x["origen"]})
            bad = acct.startswith("adm.") and any(o != "JUMP01" for o in origins)
            return (f"{acct} usado desde {', '.join(origins) or 'ningún equipo en AD'} en ±24 h"
                    + (" — las cuentas adm.* solo pueden usarse desde JUMP01" if bad else ""), bad, r, len(r))
        c.add("RB-09.lateral", f"RB-09.4 Movimiento lateral: ¿desde dónde se usó {acct}?", lateral)

    src_ip = c.ev.get("src") if re.match(r"^\d+\.\d+\.\d+\.\d+$", str(c.ev.get("src", ""))) else None
    if src_ip or "distinct_dst_hosts" in c.ev or "distinct_ports" in c.ev:
        ip = src_ip or next(iter(c.by.get("ip", [])), None)
        if ip:
            def escaneo():
                r = rows("""SELECT count(DISTINCT dst_ip) destinos, count(DISTINCT dst_port) puertos, count(*) n,
                                   count(*) FILTER (WHERE action = 'allow') permitidas, min(ts) primero, max(ts) ultimo
                            FROM firewall WHERE src_ip = ? AND ts BETWEEN ? AND ?""", [ip, iso(c.t - H), iso(c.t + H)])[0]
                return (f"{ip}: {r['n']} conexiones a {r['destinos']} destinos y {r['puertos']} puertos en ±1 h ({r['permitidas']} permitidas)",
                        (r["destinos"] or 0) > 20 or (r["puertos"] or 0) > 20, [r], r["n"])
            c.add("RB-09.escaneo", "RB-09.3 Escaneo: volumen de destinos y puertos desde el origen", escaneo)


# ------------------------------------------------------------------ RB-10 CI/CD
def rb10(c: Ctx) -> None:
    build = c.ev.get("build")
    pkg = c.ev.get("package")
    steps = rows("SELECT * FROM cicd_builds WHERE build_id = ? ORDER BY ts", [build]) if build else []
    b0 = _iso(steps[0]["ts"]) if steps else c.t

    def completo():
        if not build:
            return "la alerta no trae build", False, [], None
        txt = " ".join(json.dumps(s.get("details"), default=str) for s in steps)
        secrets = sorted(set(re.findall(SECRET_RE, txt)))
        deployed = any(s["step"] == "deploy" and s["status"] in ("ok", "success") for s in steps)
        evs = [ev(s, ["step", "status", "runner", "details"]) for s in steps]
        return (f"build {build}: {len(steps)} pasos; {'SE DESPLEGÓ' if deployed else 'no llegó a desplegarse'}"
                + (f"; secretos leídos: {', '.join(secrets)}" if secrets else ""), bool(secrets), evs, len(steps))
    c.add("RB-10.build", "RB-10.3-4 El build completo: ¿leyó secretos? ¿se desplegó?", completo)

    if pkg:
        def paquete():
            name = re.split(r"@(?=\d)", str(pkg).split()[0])[0]
            # El nombre del paquete está en el paso del build ("postinstall:puppeteer"), no en details
            r = rows("""SELECT count(DISTINCT build_id) builds, min(ts) primero FROM cicd_builds
                        WHERE (step ILIKE ? OR CAST(details AS VARCHAR) ILIKE ?) AND ts < ?""", [f"%{name}%", f"%{name}%", iso(b0)])[0]
            ev_txt = json.dumps(c.ev, ensure_ascii=False)
            secrets = sorted(set(re.findall(SECRET_RE, ev_txt)))
            wrong_registry = bool(c.ev.get("expected_package"))
            txt = (f"{name}: aparece en {r['builds']} builds anteriores" + (f" desde {r['primero']}" if r["builds"] else " — NUEVO en el CI")
                   + f"; registro: {c.ev.get('registry') or 'no indicado'}"
                   + (f"; se esperaba {c.ev['expected_package']} (posible dependency confusion)" if wrong_registry else "")
                   + (f"; lee secretos: {', '.join(secrets)}" if secrets else "; no lee secretos"))
            # RB-10.1-2: nuevo por sí solo no basta (esbuild, sharp, puppeteer descargan binarios por diseño)
            return txt, r["builds"] == 0 and (bool(secrets) or wrong_registry), [], r["builds"]
        c.add("RB-10.paquete", "RB-10.1 ¿El paquete es conocido en nuestros builds o es nuevo?", paquete)

    def credenciales():
        # Solo cuenta si ESTE build leyó credenciales de AWS: si no las leyó, el uso posterior de una clave
        # no tiene que ver con él (antes avisaban todos los builds de la semana del ataque)
        read = sorted(set(re.findall(r"AWS_[A-Z_]+", json.dumps(c.ev, ensure_ascii=False) + " ".join(
            json.dumps(s.get("details"), default=str) for s in steps))))
        if not read:
            return "el build no leyó credenciales de AWS: el uso posterior de claves no se le puede atribuir", False, [], 0
        # Identidades cloud usadas tras el build desde IPs que esa identidad nunca había usado
        r = rows("""SELECT c.* FROM cloudtrail c WHERE c.ts BETWEEN ? AND ? AND NOT EXISTS (
                        SELECT 1 FROM cloudtrail p WHERE p.userIdentity.accessKeyId = c.userIdentity.accessKeyId
                        AND p.sourceIPAddress = c.sourceIPAddress AND p.ts < ?)
                    ORDER BY c.ts LIMIT 10""", [iso(b0), iso(b0 + 3 * D), iso(b0)])
        keys = sorted({(x.get("userIdentity") or {}).get("accessKeyId") for x in r} - {None})
        evs = [ev(x, ["eventName", "userIdentity", "sourceIPAddress", "requestParameters"]) for x in r]
        return (f"el build leyó {', '.join(read)}; {len(r)} llamadas a AWS en las 72 h siguientes desde IPs nuevas para su clave"
                + (f" (claves: {', '.join(keys)})" if keys else ""), bool(r), evs, len(r))
    c.add("RB-10.credenciales", "RB-10.4 ¿Se usaron credenciales del entorno después, desde un origen nuevo? (CloudTrail, 72 h)", credenciales)


RECIPES: dict[str, Callable[[Ctx], None]] = {
    "RB-01": rb01, "RB-02": rb02, "RB-03": rb03, "RB-04": rb04, "RB-05": rb05,
    "RB-06": rb06, "RB-07": rb07, "RB-08": rb08, "RB-09": rb09, "RB-10": rb10,
}


def run_recipes(a: dict, by_type: dict[str, list[str]], tb: ToolBox) -> list[Check]:
    fn = RECIPES.get(a.get("runbook", ""))
    if not fn:
        return []
    c = Ctx(a, by_type, tb)
    try:
        fn(c)
    except Exception as e:
        c.checks.append(Check(id=f"{a.get('runbook')}.error", question="receta", answer=f"error: {type(e).__name__}: {e}"[:200]))
    return c.checks
