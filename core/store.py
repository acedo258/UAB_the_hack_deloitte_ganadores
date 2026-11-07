"""Almacén DuckDB sobre el dataset de Tarvia.  Responsable: A (datos).

Uso:
    python -m core.store            # construye data/tarvia.duckdb (≈1 min)
    from core.store import db, rows # consultas desde el resto del código

Tablas que crea:
    <fuente>          una por fichero de 04_logs (proxy, dns, edr_events...), con ts en UTC
    alerts            alertas del SIEM (columnas clave + raw JSON)
    alert_entities    (alert_id, entity, etype)  entidades normalizadas de cada alerta
    entity_events     (entity, etype, ts, source, event_id)  ÍNDICE para ±24 h y correlación
    activos, usuarios, vulnerabilidades, eventos_rrhh, calendario_cambios, servicios_negocio,
    zonas_red, tiendas, catalogo, ti_feed, geoip, sandbox

Normalización de entidades (etype):
    user   -> parte local del UPN en minúsculas, sin "TARVIA\\"  (laura.ferrer2, adm.aortega, svc_backup)
    host   -> hostname en MAYÚSCULAS
    ip     -> tal cual
    domain -> minúsculas
    hash, customer, session, access_key, message_id, app (idp_audit.target no-usuario), db_object (sql_audit.object),
    file   -> nombre de fichero en minúsculas (adjuntos de correo <-> scripts en command_line del EDR)
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

import duckdb

from core.config import DATA_DIR, DB_PATH

LOGS = DATA_DIR / "04_logs"
INV = DATA_DIR / "02_inventario"
INTEL = DATA_DIR / "05_inteligencia"
CTX = DATA_DIR / "01_contexto"

# Expresiones SQL de entidades por fuente: (etype, expresión)
U = "norm_user({})"
URL_DOMAIN = "lower(regexp_extract({}, '^[a-z]+://([^/:?#]+)', 1))"
# sha256 de adjuntos y de lo que hay dentro de los .zip (enlaza correo -> ejecución en EDR)
ATT_HASHES = ("lower(unnest(list_concat(list_transform(attachments, lambda a: a.sha256), "
              "flatten(list_transform(attachments, lambda a: coalesce(list_transform(a.contains, lambda x: x.sha256), []))))))")
ATT_NAMES = ("lower(unnest(list_concat(list_transform(attachments, lambda a: a.name), "
             "flatten(list_transform(attachments, lambda a: coalesce(list_transform(a.contains, lambda x: x.name), []))))))")
# Ficheros "de usuario" en la línea de comandos (sin .exe/.dll, que serían hubs)
_EXT = "js|jse|vbs|vbe|wsf|hta|lnk|iso|img|zip|rar|7z|ps1|bat|cmd|msi|docm|xlsm|doc|docx|xls|xlsx|pdf|one"
CMD_FILES = f"lower(unnest(regexp_extract_all(command_line, '([A-Za-z0-9_.\\-]+\\.(?:{_EXT}))\\b', 1)))"
ENTITY_MAP: dict[str, list[tuple[str, str]]] = {
    "ad_events":    [("user", U.format("subject")), ("user", U.format("target")), ("host", "upper(src_host)"), ("host", "upper(dc)")],
    "ai_gateway":   [("customer", "customer_id"), ("ip", "src_ip"), ("session", "session_id"),
                     ("customer", "unnest(list_transform(tool_calls, lambda t: t.args.customer_id))")],  # cliente víctima
    "cicd_builds":  [("host", "upper(runner)")],
    "cloudtrail":   [("user", U.format("userIdentity.userName")), ("access_key", "userIdentity.accessKeyId"), ("ip", "sourceIPAddress"),
                     ("user", U.format("requestParameters.userName"))],   # a quién crea / da permisos
    "dlp":          [("user", U.format('"user"')), ("host", "upper(hostname)"), ("domain", "lower(destination)")],
    "dns":          [("ip", "src_ip"), ("host", "upper(hostname)"), ("domain", "lower(query)")],
    "ecom_account": [("customer", "customer_id"), ("ip", "src_ip")],
    "ecom_auth":    [("customer", "customer_id"), ("ip", "src_ip")],
    "edr_events":   [("host", "upper(hostname)"), ("user", U.format('"user"')), ("hash", "lower(sha256)"),
                     ("file", CMD_FILES)],   # el sha256 del EDR es el del intérprete; el script se ve por nombre
    "email":        [("user", U.format("sender")), ("ip", "sender_ip"), ("message_id", "message_id"),
                     ("user", U.format("unnest(recipients)")),
                     ("hash", ATT_HASHES), ("file", ATT_NAMES), ("domain", URL_DOMAIN.format("unnest(urls)"))],
    "email_clicks": [("user", U.format('"user"')), ("ip", "src_ip"), ("message_id", "message_id"),
                     ("domain", URL_DOMAIN.format("url"))],
    "firewall":     [("ip", "src_ip"), ("ip", "dst_ip")],
    "idp_audit":    [("user", U.format("actor_upn")), ("ip", "src_ip"),
                     ("user", f"CASE WHEN target LIKE '%@%' THEN {U.format('target')} END"),   # target puede ser usuario...
                     ("app", "CASE WHEN target NOT LIKE '%@%' THEN target END")],              # ...o app OAuth/carpeta
    "idp_signins":  [("user", U.format("user_upn")), ("ip", "src_ip"), ("session", "session_id")],
    "proxy":        [("ip", "src_ip"), ("host", "upper(hostname)"), ("user", U.format('"user"')), ("domain", "lower(domain)"), ("ip", "dst_ip")],
    "sql_audit":    [("user", U.format('"user"')), ("host", "upper(client_host)"), ("db_object", "lower(object)")],
    "vpn":          [("user", U.format('"user"')), ("ip", "src_ip"), ("ip", "assigned_ip")],
    "waf":          [("ip", "src_ip")],
}

_local = threading.local()


def db(read_only: bool = True) -> duckdb.DuckDBPyConnection:
    """Conexión por hilo (DuckDB no comparte conexiones entre hilos)."""
    con = getattr(_local, "con", None)
    if con is None:
        if not DB_PATH.exists():
            raise RuntimeError(f"No existe {DB_PATH}. Ejecuta antes: python -m core.store")
        con = duckdb.connect(str(DB_PATH), read_only=read_only)
        con.execute("SET TimeZone='UTC'")
        _local.con = con
    return con


def rows(sql: str, params: list | None = None) -> list[dict[str, Any]]:
    """Ejecuta SQL y devuelve una lista de dicts (fechas como texto ISO)."""
    cur = db().execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        d = {}
        for c, v in zip(cols, r):
            if hasattr(v, "isoformat"):
                v = v.isoformat().replace("+00:00", "Z")
            elif isinstance(v, str) and c == "raw":
                v = json.loads(v)
            d[c] = v
        out.append(d)
    return out


def norm_user(x: str | None) -> str | None:
    """Misma normalización que la macro SQL, para usar desde Python."""
    if not x:
        return None
    x = x.strip().lower()
    if x.startswith("tarvia\\"):
        x = x[7:]
    if x.endswith("@tarvia.example"):
        x = x[: -len("@tarvia.example")]
    return x or None


def url_domain(url: str | None) -> str | None:
    """Igual que URL_DOMAIN en SQL: 'https://www.x.example/a' -> 'www.x.example'."""
    m = re.match(r"^[a-z]+://([^/:?#]+)", (url or "").strip().lower())
    return m.group(1) if m else None


# ------------------------------------------------------------------ construcción
def _src_sql(path: Path) -> str:
    if path.suffix == ".jsonl":
        return f"read_json('{path}', format='newline_delimited', sample_size=-1, union_by_name=true)"
    return f"read_csv('{path}', header=true, all_varchar=true)"


def _ts_expr(path: Path) -> str:
    # En los CSV el timestamp llega como texto
    return "CAST(\"timestamp\" AS TIMESTAMPTZ)" if path.suffix == ".csv" else "\"timestamp\""


def build(verbose: bool = True) -> None:
    t0 = time.time()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    con = duckdb.connect(str(DB_PATH))
    con.execute("SET TimeZone='UTC'")
    con.execute(r"""CREATE MACRO norm_user(x) AS nullif(
        regexp_replace(regexp_replace(lower(trim(x)), '^tarvia\\', ''), '@tarvia\.example$', ''), '')""")

    def log(msg):
        if verbose:
            print(f"[{time.time() - t0:5.1f}s] {msg}")

    # --- logs
    con.execute("CREATE TABLE entity_events(entity VARCHAR, etype VARCHAR, ts TIMESTAMPTZ, source VARCHAR, event_id VARCHAR)")
    for path in sorted(LOGS.iterdir()):
        name = path.stem
        con.execute(f"CREATE TABLE {name} AS SELECT * REPLACE ({_ts_expr(path)} AS \"timestamp\") FROM {_src_sql(path)}")
        con.execute(f"ALTER TABLE {name} RENAME COLUMN \"timestamp\" TO ts")
        n = con.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
        for etype, expr in ENTITY_MAP.get(name, []):
            con.execute(f"""INSERT INTO entity_events
                SELECT e, '{etype}', ts, '{name}', event_id FROM (SELECT {expr} AS e, ts, event_id FROM {name})
                WHERE e IS NOT NULL AND e <> ''""")
        log(f"{name}: {n:,} eventos")

    # --- inventario e inteligencia
    for path in sorted(INV.glob("*.csv")):
        con.execute(f"CREATE TABLE {path.stem} AS SELECT * FROM read_csv('{path}', header=true, all_varchar=true)")
    con.execute(f"CREATE TABLE catalogo AS SELECT * FROM read_csv('{CTX / 'catalogo_casos_de_uso.csv'}', header=true, all_varchar=true)")
    con.execute(f"CREATE TABLE ti_feed AS SELECT * FROM {_src_sql(INTEL / 'ti_feed.jsonl')}")
    con.execute(f"CREATE TABLE geoip AS SELECT * FROM read_csv('{INTEL / 'geoip_asn.csv'}', header=true, all_varchar=true)")
    con.execute(f"CREATE TABLE sandbox AS SELECT sha256, to_json(s) AS raw FROM {_src_sql(INTEL / 'sandbox_informes.jsonl')} s")
    log("inventario e inteligencia")

    # --- alertas (estructura muy variable: guardamos raw JSON + columnas clave)
    con.execute("""CREATE TABLE alerts(alert_id VARCHAR PRIMARY KEY, created_at TIMESTAMPTZ, source_product VARCHAR,
                   rule_id VARCHAR, rule_name VARCHAR, severity VARCHAR, runbook VARCHAR, dev_sample BOOLEAN, raw JSON)""")
    con.execute("CREATE TABLE alert_entities(alert_id VARCHAR, entity VARCHAR, etype VARCHAR)")
    dev_ids = {json.loads(l)["alert_id"] for l in open(DATA_DIR / "03_alertas" / "alertas_muestra_desarrollo.jsonl", encoding="utf-8") if l.strip()}
    a_rows, e_rows = [], []
    for line in open(DATA_DIR / "03_alertas" / "alertas.jsonl", encoding="utf-8"):
        if not line.strip():
            continue
        a = json.loads(line)
        a_rows.append((a["alert_id"], a["created_at"], a["source_product"], a["rule_id"], a["rule_name"],
                       a["severity"], a.get("runbook", ""), a["alert_id"] in dev_ids, json.dumps(a, ensure_ascii=False)))
        e_rows += [(a["alert_id"], e, t) for e, t in alert_entities(a)]
    # executemany es muy lento en DuckDB: volcamos a ficheros temporales y los leemos de golpe
    tmp = DB_PATH.parent / "_tmp_alerts.jsonl"
    cols = ["alert_id", "created_at", "source_product", "rule_id", "rule_name", "severity", "runbook", "dev_sample", "raw"]
    with open(tmp, "w", encoding="utf-8") as f:
        for r in a_rows:
            f.write(json.dumps(dict(zip(cols, r)), ensure_ascii=False) + "\n")
    con.execute(f"""INSERT INTO alerts SELECT alert_id, CAST(created_at AS TIMESTAMPTZ), source_product, rule_id, rule_name,
        severity, runbook, dev_sample, CAST(raw AS JSON) FROM read_json('{tmp}', format='newline_delimited',
        columns={{alert_id:'VARCHAR', created_at:'VARCHAR', source_product:'VARCHAR', rule_id:'VARCHAR', rule_name:'VARCHAR',
                  severity:'VARCHAR', runbook:'VARCHAR', dev_sample:'BOOLEAN', raw:'VARCHAR'}})""")
    with open(tmp, "w", encoding="utf-8") as f:
        for r in e_rows:
            f.write(json.dumps({"alert_id": r[0], "entity": r[1], "etype": r[2]}, ensure_ascii=False) + "\n")
    con.execute(f"INSERT INTO alert_entities SELECT * FROM read_json('{tmp}', format='newline_delimited', "
                "columns={alert_id:'VARCHAR', entity:'VARCHAR', etype:'VARCHAR'})")
    tmp.unlink()
    log(f"alertas: {len(a_rows):,} ({len(e_rows):,} entidades)")

    # --- índices
    con.execute("CREATE INDEX ix_ee ON entity_events(entity)")
    con.execute("CREATE INDEX ix_ae ON alert_entities(entity)")
    n = con.execute("SELECT count(*) FROM entity_events").fetchone()[0]
    log(f"entity_events: {n:,} filas")

    # --- hubs: entidades compartidas por tanta gente que no relacionan nada
    build_hubs(con)
    h = con.execute("SELECT kind, count(*) FROM hub_entities GROUP BY 1 ORDER BY 1").fetchall()
    log(f"hub_entities: {', '.join(f'{k} {v}' for k, v in h)}. Listo: {DB_PATH}")
    con.close()


# ------------------------------------------------------------------ hubs
# Umbrales sobre una empresa de ~1.200 empleados y ~1.200 equipos (ver docs de la parte A)
HUB_SHARED = 20          # IP / equipo / cuenta / hash compartido por >= 20 usuarios o equipos distintos
HUB_DOMAIN_HOSTS = 50    # dominio que visitan >= 50 equipos (~4 % de la red)
HUB_ALERTS = 30          # entidad en >= 30 alertas...
OWN_DOMAIN = "tarvia.example"


def build_hubs(con) -> None:
    """Crea hub_entities(entity, etype, kind, spread, reason).

    kind = 'hub'      -> no relaciona nada: se excluye de la línea temporal, de "otras alertas" y de la correlación.
    kind = 'campaign' -> muchas alertas de UNA sola regla (misma campaña o mismo ruido): lo agrupa fingerprint.py;
                         la correlación no debería usarla para unir incidentes distintos.
    El reparto se mide por co-aparición en el mismo evento: (source, event_id) compartido en entity_events."""
    con.execute("DROP TABLE IF EXISTS hub_entities")
    con.execute("CREATE TABLE hub_entities(entity VARCHAR, etype VARCHAR, kind VARCHAR, spread BIGINT, reason VARCHAR)")

    def spread(a: str, b: str, threshold: int, reason: str) -> None:
        con.execute(f"""INSERT INTO hub_entities
            SELECT x.entity, x.etype, 'hub', count(DISTINCT y.entity) n, '{reason}: ' || count(DISTINCT y.entity)
            FROM entity_events x JOIN entity_events y ON x.source = y.source AND x.event_id = y.event_id AND y.etype = '{b}'
            WHERE x.etype = '{a}' AND x.entity <> y.entity GROUP BY 1, 2 HAVING count(DISTINCT y.entity) >= {threshold}""")

    spread("ip", "user", HUB_SHARED, "IP compartida por usuarios distintos")
    spread("host", "user", HUB_SHARED, "equipo compartido por usuarios distintos")
    spread("user", "host", HUB_SHARED, "cuenta usada en equipos distintos")
    spread("hash", "host", HUB_SHARED, "hash visto en equipos distintos")
    spread("domain", "host", HUB_DOMAIN_HOSTS, "dominio visitado por equipos distintos")
    # Dominio propio: tarvia.example y todos sus subdominios
    con.execute(f"""INSERT INTO hub_entities SELECT DISTINCT entity, 'domain', 'hub', NULL, 'dominio propio de la empresa'
                    FROM (SELECT entity FROM entity_events WHERE etype = 'domain' UNION SELECT entity FROM alert_entities WHERE etype = 'domain')
                    WHERE (entity = '{OWN_DOMAIN}' OR entity LIKE '%.{OWN_DOMAIN}')
                    AND entity NOT IN (SELECT entity FROM hub_entities)""")
    # Desde las alertas: muchas alertas y varias reglas = hub; muchas alertas de una sola regla = campaña
    con.execute(f"""INSERT INTO hub_entities
        SELECT e.entity, e.etype, CASE WHEN count(DISTINCT a.rule_id) >= 2 THEN 'hub' ELSE 'campaign' END,
               count(DISTINCT e.alert_id),
               CASE WHEN count(DISTINCT a.rule_id) >= 2 THEN 'en ' || count(DISTINCT e.alert_id) || ' alertas de ' || count(DISTINCT a.rule_id) || ' reglas'
                    ELSE 'campaña o ruido repetido: ' || count(DISTINCT e.alert_id) || ' alertas de la regla ' || any_value(a.rule_id) END
        FROM alert_entities e JOIN alerts a USING (alert_id)
        WHERE e.entity NOT IN (SELECT entity FROM hub_entities)
        GROUP BY 1, 2 HAVING count(DISTINCT e.alert_id) >= {HUB_ALERTS}""")
    con.execute("CREATE INDEX ix_hub ON hub_entities(entity)")


_HUBS: dict[str, dict] | None = None


def hubs() -> dict[str, dict]:
    """{entity: {etype, kind, reason}} cargado una vez por proceso. Vacío si la base es anterior al bloque 4."""
    global _HUBS
    if _HUBS is None:
        try:
            _HUBS = {r["entity"]: r for r in rows("SELECT entity, etype, kind, reason FROM hub_entities")}
        except Exception:
            _HUBS = {}
    return _HUBS


def is_hub(entity: str | None, include_campaigns: bool = False) -> bool:
    h = hubs().get(entity or "")
    return bool(h) and (include_campaigns or h["kind"] == "hub")


def alert_entities(a: dict) -> list[tuple[str, str]]:
    """Extrae entidades normalizadas de una alerta (también sirve para alertas nuevas del domingo)."""
    ent = a.get("entities", {}) or {}
    out: set[tuple[str, str]] = set()
    for u in ent.get("users", []) or []:
        if (k := norm_user(u.get("upn") or u.get("username"))):
            out.add((k, "user"))
    for h in ent.get("hosts", []) or []:
        if h.get("hostname"):
            out.add((h["hostname"].upper(), "host"))
        if h.get("ip"):
            out.add((h["ip"], "ip"))
    for ip in ent.get("ips", []) or []:
        out.add((ip, "ip"))
    for d in ent.get("domains", []) or []:
        out.add((d.lower(), "domain"))
    for f in ent.get("files", []) or []:
        if f.get("sha256"):
            out.add((f["sha256"].lower(), "hash"))
        if f.get("name"):
            out.add((f["name"].lower(), "file"))
    for u in ent.get("urls", []) or []:
        if (d := url_domain(u)):
            out.add((d, "domain"))
    for c in ent.get("customers", []) or []:
        if c.get("customer_id"):
            out.add((c["customer_id"], "customer"))
    cloud = ent.get("cloud") or {}
    if cloud.get("access_key"):
        out.add((cloud["access_key"], "access_key"))
    for k in ("identity", "new_user"):
        if cloud.get(k):
            out.add((cloud[k].lower(), "user"))
    if ent.get("ai_session"):
        out.add((ent["ai_session"], "session"))
    ev = a.get("evidence", {}) or {}
    if ev.get("message_id"):
        out.add((ev["message_id"], "message_id"))
    return sorted(out)


if __name__ == "__main__":
    build()
