"""Comparación con lo habitual ("¿es la primera vez que…?").  Responsable: A (datos).

Seis preguntas genéricas que sirven para CUALQUIER alerta, no solo para un runbook:

    user_origin   ¿este usuario había entrado antes desde este país / ASN / IP?
    host_domain   ¿este equipo había contactado antes este dominio? ¿cuántos equipos lo hacen?
    prevalence    ¿en cuántos equipos se ha visto este hash o este fichero?
    account_host  ¿esta cuenta se había usado antes en este equipo?
    user_hours    ¿es una hora habitual para este usuario?
    key_origin    ¿esta clave de AWS se había usado antes desde esta IP?

Cada una devuelve un Check (el mismo contrato que las recetas, con id "BL.<pregunta>") y se añade a pack.checks.

Reglas para no dar falsas alarmas:
  - "Antes" = todo el historial hasta 1 h antes de la alerta (así la propia actividad de la alerta no cuenta).
  - Sin historial suficiente (MIN_HISTORY eventos) NO se avisa: se dice "sin historial suficiente".
    Nuevo no significa malo, y desconocido no significa nuevo.
  - Lo que hace todo el mundo (un dominio que visitan cientos de equipos) nunca es anómalo.
Los logs cubren unas 4 semanas (5/10 a 1/11/2026): "primera vez" quiere decir "primera vez en ese periodo".
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from core.schemas import Check
from core.store import norm_user, rows
from core.tools import ToolBox, _iso

MIN_HISTORY = 5           # eventos previos mínimos para opinar
RARE_HOSTS = 2            # visto en <= N equipos = raro
COMMON_ASN_USERS = 5      # más de N empleados entran desde ese ASN = infraestructura común, no anómalo
HOUR_RARE = 0.03          # < 3 % de la actividad previa en esa franja = hora inusual
GAP = timedelta(hours=1)

# Hora local (UTC+2 hasta el 25/10/2026 01:00 UTC, UTC+1 después), en SQL
LOCAL_HOUR = "hour(ts + CASE WHEN ts < TIMESTAMPTZ '2026-10-25 01:00:00+00' THEN INTERVAL 2 HOUR ELSE INTERVAL 1 HOUR END)"


def _before(t: datetime) -> str:
    return (t - GAP).isoformat()


def _local_hour(t: datetime) -> int:
    off = 2 if t < datetime(2026, 10, 25, 1, tzinfo=t.tzinfo) else 1
    return (t + timedelta(hours=off)).hour


def _check(cid: str, q: str, answer: str, attention: bool = False, facts: dict | None = None, count: int | None = None) -> Check:
    return Check(id=cid, question=q, answer=answer, attention=attention, count=count, events=[facts] if facts else [])


# ------------------------------------------------------------------ las seis preguntas
def user_origin(user: str, ip: str, ts: str) -> Check:
    t, u = _iso(ts), norm_user(user)
    q = f"¿{u} había entrado antes desde {ip} (su país / ASN)?"
    g = rows("SELECT country, asn, as_org FROM geoip WHERE ip = ?", [ip])
    if not g:   # sin GeoIP: probamos con lo que dice el propio log de inicio de sesión
        g = rows("SELECT country, asn, NULL AS as_org FROM idp_signins WHERE src_ip = ? LIMIT 1", [ip])
    country, asn = (g[0]["country"], str(g[0]["asn"])) if g else (None, None)
    # VPN no trae ASN: lo cruzamos con GeoIP para que el historial de cuentas solo-VPN también tenga ASN
    r = rows("""WITH prev AS (
                  SELECT src_ip, country, CAST(asn AS VARCHAR) asn, ts FROM idp_signins WHERE norm_user(user_upn) = ? AND ts < ?
                  UNION ALL SELECT v.src_ip, v.country, CAST(g.asn AS VARCHAR), v.ts FROM vpn v LEFT JOIN geoip g ON g.ip = v.src_ip
                            WHERE norm_user(v."user") = ? AND v.ts < ? AND v.action <> 'disconnect')
                SELECT count(*) total, count(*) FILTER (WHERE src_ip = ?) ip_n,
                       count(*) FILTER (WHERE country = ?) pais_n, count(*) FILTER (WHERE asn = ?) asn_n,
                       count(*) FILTER (WHERE asn IS NOT NULL) con_asn,
                       list(DISTINCT country) FILTER (WHERE country IS NOT NULL) paises
                FROM prev""", [u, _before(t), u, _before(t), ip, country, asn])[0]
    # Envenenamiento de la línea base: si las veces anteriores desde esta IP ya dispararon alertas, no es "habitual"
    alerted = rows("""SELECT count(DISTINCT a.alert_id) n FROM alerts a
                      JOIN alert_entities ei ON ei.alert_id = a.alert_id AND ei.etype = 'ip' AND ei.entity = ?
                      JOIN alert_entities eu ON eu.alert_id = a.alert_id AND eu.etype = 'user' AND eu.entity = ?
                      WHERE a.created_at < ?""", [ip, u, _before(t)])[0]["n"]
    # ¿Cuántos OTROS empleados entran desde ese ASN? Si son muchos, es infraestructura común (nube, operador, salida corporativa)
    asn_users = rows("""SELECT count(DISTINCT norm_user(user_upn)) n FROM idp_signins
                        WHERE CAST(asn AS VARCHAR) = ? AND norm_user(user_upn) <> ? AND result = 'success'""", [asn, u])[0]["n"] if asn else 0
    facts = {"ip": ip, "pais": country, "asn": (g[0].get("as_org") if g else None) or asn, "historial": r["total"],
             "otros_empleados_desde_ese_asn": asn_users,
             "veces_ip": r["ip_n"], "veces_pais": r["pais_n"], "veces_asn": r["asn_n"],
             "alertas_previas_desde_esta_ip": alerted, "paises_habituales": sorted(r["paises"] or [])[:6]}
    fixed = fixed_origin(u)
    if r["total"] < (2 if fixed else MIN_HISTORY):
        return _check("BL.user_origin", q, f"{u}: sin historial suficiente ({r['total']} inicios previos)", False, facts, r["total"])
    if not country:
        return _check("BL.user_origin", q, f"{ip}: país desconocido; IP vista {r['ip_n']} veces para {u}", False, facts, r["ip_n"])
    new_country = r["pais_n"] == 0
    # Un ASN solo es "nuevo" si conocemos el ASN del historial y la IP no se había usado nunca
    new_asn = asn is not None and r["con_asn"] > 0 and r["asn_n"] == 0 and r["ip_n"] == 0
    # Mayoría de las apariciones con alerta = origen ya alertado que se repite (las reglas también saltan con lo legítimo)
    seen_only_in_alerts = r["ip_n"] > 0 and alerted / r["ip_n"] >= 0.5
    common_asn = asn_users > COMMON_ASN_USERS
    if new_country:
        txt = (f"PRIMERA VEZ que {u} entra desde {country} (sus {r['total']} inicios previos: {', '.join(facts['paises_habituales'])})"
               + (f"; pero desde ese ASN ({facts['asn']}) entran otros {asn_users} empleados: infraestructura común" if common_asn
                  else f"; y desde ese ASN ({facts['asn']}) no entra casi nadie más de la empresa ({asn_users})"))
    elif seen_only_in_alerts:
        txt = (f"{ip} ({country}) ya se había usado {r['ip_n']} veces con {u}, y {alerted} de ellas generaron alerta: "
               f"es un origen ya alertado que se repite, no un origen habitual")
    elif new_asn:
        txt = (f"{u} ya había entrado desde {country}, pero nunca desde ese ASN ({facts['asn']})"
               + (" — es una cuenta de origen fijo (externa, de servicio o admin): un ASN nuevo es anómalo" if fixed else ""))
    else:
        txt = (f"origen habitual: {u} había entrado {r['pais_n']} veces desde {country} y {r['ip_n']} desde esa IP"
               + (f" ({alerted} con alerta, una minoría)" if alerted else ""))
    return _check("BL.user_origin", q, txt, (new_country and not common_asn) or seen_only_in_alerts or (new_asn and fixed and not common_asn),
                  facts, r["pais_n"])


def fixed_origin(u: str) -> bool:
    """Cuentas externas, de servicio y de administración: deberían conectarse siempre desde los mismos sitios."""
    return bool(u) and u.startswith(("ext.", "svc_", "adm."))


def host_domain(host: str, domain: str, ts: str) -> Check:
    t, h, d = _iso(ts), host.upper(), domain.lower()
    q = f"¿{h} había contactado antes {d}? ¿Cuántos equipos lo hacen?"
    r = rows("""WITH ev AS (SELECT upper(hostname) h, ts FROM proxy WHERE lower(domain) = ?
                            UNION ALL SELECT upper(hostname), ts FROM dns WHERE lower(query) = ? OR lower(query) LIKE ?)
                SELECT count(*) FILTER (WHERE h = ? AND ts < ?) antes_este,
                       count(DISTINCT h) equipos, count(DISTINCT h) FILTER (WHERE ts < ?) equipos_antes, min(ts) primero
                FROM ev""", [d, d, f"%.{d}", h, _before(t), _before(t)])[0]
    hist = rows("SELECT count(*) n FROM proxy WHERE upper(hostname) = ? AND ts < ?", [h, _before(t)])[0]["n"]
    facts = {"equipo": h, "dominio": d, "veces_antes_este_equipo": r["antes_este"], "equipos_que_lo_contactan": r["equipos"],
             "equipos_antes_de_la_alerta": r["equipos_antes"], "visto_por_primera_vez": r["primero"]}
    if r["equipos"] > RARE_HOSTS:
        return _check("BL.host_domain", q, f"{d}: lo contactan {r['equipos']} equipos de la red; no es raro", False, facts, r["equipos"])
    if hist < MIN_HISTORY:
        return _check("BL.host_domain", q, f"{h}: sin historial de navegación suficiente", False, facts, r["equipos"])
    first = r["antes_este"] == 0
    return _check("BL.host_domain", q,
                  f"{d}: solo {r['equipos']} equipo(s) en toda la red lo contactan"
                  + (f", y es la PRIMERA VEZ para {h}" if first else f"; {h} ya lo había contactado {r['antes_este']} veces"),
                  True, facts, r["equipos"])


def prevalence(indicator: str, ts: str) -> Check:
    """Hash (sha256) o nombre de fichero: ¿en cuántos equipos se ha visto?"""
    ind = indicator.lower()
    kind = "hash" if re.fullmatch(r"[0-9a-f]{64}", ind) else "file"
    q = f"¿En cuántos equipos se ha visto {ind[:20] + '…' if kind == 'hash' else ind}?"
    if kind == "hash":
        r = rows("""SELECT count(DISTINCT upper(hostname)) equipos, count(*) n, any_value(process_name) nombre,
                           any_value(signer) firma, min(ts) primero FROM edr_events WHERE lower(sha256) = ?""", [ind])[0]
    else:
        r = rows("""SELECT count(DISTINCT upper(e.hostname)) equipos, count(*) n, any_value(e.process_name) nombre,
                           any_value(e.signer) firma, min(e.ts) primero
                    FROM entity_events x JOIN edr_events e USING (event_id)
                    WHERE x.etype = 'file' AND x.source = 'edr_events' AND x.entity = ?""", [ind])[0]
    facts = {"indicador": indicator, "tipo": kind, "equipos": r["equipos"], "ejecuciones": r["n"], "proceso": r["nombre"],
             "firma": r["firma"], "primero": r["primero"]}
    if r["n"] == 0:
        return _check("BL.prevalence", q, f"{kind} no visto en el EDR (desconocido, no limpio)", False, facts, 0)
    rare = r["equipos"] <= RARE_HOSTS
    return _check("BL.prevalence", q,
                  f"{r['nombre'] or kind} visto en {r['equipos']} equipo(s), {r['n']} veces"
                  + (" — RARO en la red" if rare else " — habitual en la red"), rare, facts, r["equipos"])


def account_host(user: str, host: str, ts: str) -> Check:
    t, u, h = _iso(ts), norm_user(user), host.upper()
    q = f"¿{u} se había usado antes en {h}?"
    r = rows("""WITH ev AS (SELECT upper(hostname) h, ts FROM edr_events WHERE norm_user("user") = ?
                            UNION ALL SELECT upper(src_host), ts FROM ad_events WHERE norm_user(subject) = ?
                            UNION ALL SELECT upper(hostname), ts FROM proxy WHERE norm_user("user") = ?)
                SELECT count(*) FILTER (WHERE ts < ?) total, count(*) FILTER (WHERE h = ? AND ts < ?) aqui,
                       list(DISTINCT h) FILTER (WHERE ts < ? AND h IS NOT NULL) equipos FROM ev""",
             [u, u, u, _before(t), h, _before(t), _before(t)])[0]
    usual = sorted(r["equipos"] or [])
    facts = {"cuenta": u, "equipo": h, "veces_aqui_antes": r["aqui"], "historial": r["total"], "equipos_habituales": usual[:6]}
    if r["total"] < MIN_HISTORY:
        return _check("BL.account_host", q, f"{u}: sin historial suficiente en equipos", False, facts, r["total"])
    if r["aqui"]:
        return _check("BL.account_host", q, f"habitual: {u} se había usado {r['aqui']} veces en {h}", False, facts, r["aqui"])
    return _check("BL.account_host", q,
                  f"PRIMERA VEZ que {u} se usa en {h}; sus equipos habituales: {', '.join(usual[:4])}"
                  + (f" y {len(usual) - 4} más" if len(usual) > 4 else ""), True, facts, 0)


def user_hours(user: str, ts: str) -> Check:
    t, u = _iso(ts), norm_user(user)
    hr = _local_hour(t)
    q = f"¿Es habitual que {u} tenga actividad a las {hr:02d}h (hora de España)?"
    r = rows(f"""WITH ev AS (SELECT ts FROM idp_signins WHERE norm_user(user_upn) = ? AND ts < ?
                             UNION ALL SELECT ts FROM vpn WHERE norm_user("user") = ? AND ts < ?
                             UNION ALL SELECT ts FROM proxy WHERE norm_user("user") = ? AND ts < ?)
                 SELECT count(*) total,
                        count(*) FILTER (WHERE abs({LOCAL_HOUR} - ?) <= 1 OR abs({LOCAL_HOUR} - ?) >= 23) franja,
                        min({LOCAL_HOUR}) desde, max({LOCAL_HOUR}) hasta,
                        approx_quantile({LOCAL_HOUR}, 0.05) p5, approx_quantile({LOCAL_HOUR}, 0.95) p95 FROM ev""",
             [u, _before(t), u, _before(t), u, _before(t), hr, hr])[0]
    facts = {"usuario": u, "hora_local": hr, "historial": r["total"], "actividad_en_esa_franja": r["franja"],
             "horario_habitual": f"{r['p5']}h–{r['p95']}h" if r["total"] else None}
    if r["total"] < 20:
        return _check("BL.user_hours", q, f"{u}: sin historial suficiente para su horario", False, facts, r["total"])
    share = r["franja"] / r["total"]
    rare = share < HOUR_RARE
    return _check("BL.user_hours", q,
                  f"{hr:02d}h: {share:.0%} de la actividad previa de {u} cae en esa franja (habitual {r['p5']}h–{r['p95']}h)"
                  + (" — hora INUSUAL" if rare else ""), rare, facts, r["franja"])


def key_origin(access_key: str, ip: str, ts: str) -> Check:
    """access_key = una clave AWS (AKIA…) o el nombre de una identidad cloud (backup-sync)."""
    t = _iso(ts)
    q = f"¿{access_key} se había usado antes desde {ip}?"
    r = rows("""SELECT count(*) FILTER (WHERE ts < ?) total, count(*) FILTER (WHERE ts < ? AND sourceIPAddress = ?) ip_n,
                       list(DISTINCT sourceIPAddress) FILTER (WHERE ts < ?) ips FROM cloudtrail
                WHERE userIdentity.accessKeyId = ? OR norm_user(userIdentity.userName) = ?""",
             [_before(t), _before(t), ip, _before(t), access_key, norm_user(access_key)])[0]
    facts = {"clave": access_key, "ip": ip, "usos_previos": r["total"], "veces_desde_esa_ip": r["ip_n"], "ips_habituales": sorted(r["ips"] or [])[:5]}
    if r["total"] == 0:
        return _check("BL.key_origin", q, f"{access_key}: sin ningún uso previo en AWS (recién creada o nunca usada) y ahora se usa desde {ip}", True, facts, 0)
    if r["ip_n"]:
        return _check("BL.key_origin", q, f"habitual: {r['ip_n']} usos previos desde {ip}", False, facts, r["ip_n"])
    return _check("BL.key_origin", q, f"PRIMERA VEZ desde {ip}; antes solo desde {', '.join(facts['ips_habituales'])}", True, facts, 0)


QUESTIONS = {"user_origin": user_origin, "host_domain": host_domain, "prevalence": prevalence,
             "account_host": account_host, "user_hours": user_hours, "key_origin": key_origin}


# ------------------------------------------------------------------ para el pack de una alerta
def run_baselines(a: dict, by_type: dict[str, list[str]], tb: ToolBox, users: list[str], hosts: list[str], ext_ips: list[str]) -> list[Check]:
    """Elige qué preguntas tienen sentido según las entidades de la alerta (máx. ~8, para no inflar el pack)."""
    ts = a["created_at"]
    t = _iso(ts)
    # Solo IPs desde las que ESE usuario inició sesión de verdad cerca de la alerta (no la IP de un remitente, p. ej.)
    login_ips = [x["ip"] for x in rows(f"""SELECT DISTINCT src_ip ip FROM (
                    SELECT src_ip, user_upn u, ts FROM idp_signins UNION ALL SELECT src_ip, "user", ts FROM vpn)
                 WHERE norm_user(u) = ? AND src_ip IN ({",".join("?" * len(ext_ips))}) AND ts BETWEEN ? AND ? LIMIT 2""",
                 [users[0]] + ext_ips + [(t - timedelta(days=1)).isoformat(), (t + timedelta(days=1)).isoformat()])] if users and ext_ips else []
    domains = [d for d in by_type.get("domain", []) if not d.endswith("tarvia.example")][:2]
    plan: list[tuple[str, tuple]] = []
    for u in users[:1]:
        for ip in login_ips:
            plan.append(("user_origin", (u, ip, ts)))
        plan.append(("user_hours", (u, ts)))
        for h in hosts[:1]:
            plan.append(("account_host", (u, h, ts)))
    for h in hosts[:1]:
        for d in domains:
            plan.append(("host_domain", (h, d, ts)))
    # Ficheros antes que hashes: el hash del EDR suele ser el del intérprete, no el del script
    for x in (by_type.get("file", []) + by_type.get("hash", []))[:2]:
        plan.append(("prevalence", (x, ts)))
    cloud = (a.get("entities") or {}).get("cloud") or {}
    for k in (by_type.get("access_key", []) + ([cloud["identity"]] if cloud.get("identity") else []))[:1]:
        for ip in ext_ips[:1]:
            plan.append(("key_origin", (k, ip, ts)))

    out: list[Check] = []
    for name, args in plan[:8]:
        try:
            c = tb._run(f"baseline.{name}", {"args": [str(x) for x in args]}, lambda n=name, a_=args: QUESTIONS[n](*a_),
                        lambda c: ("⚠ " if c.attention else "") + c.answer)
        except Exception as e:  # una comparación rota no tumba el pack
            c = Check(id=f"BL.{name}", question=name, answer=f"no se pudo comprobar ({type(e).__name__}: {e})"[:200])
        # "Sin historial" y "no visto" no aportan al LLM: quedan en la traza, no en el pack
        if not re.search(r"sin historial suficiente|no visto en el EDR", c.answer):
            out.append(c)
    return out
