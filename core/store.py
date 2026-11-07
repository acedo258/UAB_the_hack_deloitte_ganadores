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
    hash, customer, session, access_key, message_id
"""
from __future__ import annotations

import json
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
ENTITY_MAP: dict[str, list[tuple[str, str]]] = {
    "ad_events":    [("user", U.format("subject")), ("user", U.format("target")), ("host", "upper(src_host)"), ("host", "upper(dc)")],
    "ai_gateway":   [("customer", "customer_id"), ("ip", "src_ip"), ("session", "session_id")],
    "cicd_builds":  [("host", "upper(runner)")],
    "cloudtrail":   [("user", U.format("userIdentity.userName")), ("access_key", "userIdentity.accessKeyId"), ("ip", "sourceIPAddress")],
    "dlp":          [("user", U.format('"user"')), ("host", "upper(hostname)"), ("domain", "lower(destination)")],
    "dns":          [("ip", "src_ip"), ("host", "upper(hostname)"), ("domain", "lower(query)")],
    "ecom_account": [("customer", "customer_id"), ("ip", "src_ip")],
    "ecom_auth":    [("customer", "customer_id"), ("ip", "src_ip")],
    "edr_events":   [("host", "upper(hostname)"), ("user", U.format('"user"')), ("hash", "lower(sha256)")],
    "email":        [("user", U.format("sender")), ("ip", "sender_ip"), ("message_id", "message_id"),
                     ("user", U.format("unnest(recipients)"))],
    "email_clicks": [("user", U.format('"user"')), ("ip", "src_ip"), ("message_id", "message_id")],
    "firewall":     [("ip", "src_ip"), ("ip", "dst_ip")],
    "idp_audit":    [("user", U.format("actor_upn")), ("ip", "src_ip")],
    "idp_signins":  [("user", U.format("user_upn")), ("ip", "src_ip"), ("session", "session_id")],
    "proxy":        [("ip", "src_ip"), ("host", "upper(hostname)"), ("user", U.format('"user"')), ("domain", "lower(domain)"), ("ip", "dst_ip")],
    "sql_audit":    [("user", U.format('"user"')), ("host", "upper(client_host)")],
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
    log(f"entity_events: {n:,} filas. Listo: {DB_PATH}")
    con.close()


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
