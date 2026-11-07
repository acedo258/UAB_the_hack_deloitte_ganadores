"""Correlación de incidentes: une en un incidente las alertas de una misma cadena de ataque.
Responsable: A (datos) con D (criterio).  La consola (api/server.py) llama a compute_incidents().

    python -m core.correlate            # recalcula, guarda la caché y muestra los incidentes
    python -m core.correlate --fast     # sin entidades descubiertas por las recetas (segundos, menos uniones)
    from core.correlate import compute_incidents
    incs = compute_incidents()          # lista con el formato que pinta IncidentsView.vue

Cómo decide (todo regla genérica; NUNCA mira eval/gold.jsonl):
  1. Candidatas: se quitan las alertas de patrones repetidos grandes (>= NOISE_PATTERN_MIN alertas con la misma
     huella de core/fingerprint.py), salvo las atípicas. El ruido repetido no es una cadena de ataque.
  2. Entidades de cada candidata: las de la alerta (alert_entities), sin hubs ni campañas (hub_entities), más
       - las que DESCUBREN las recetas que avisan (attention): la cuenta que entró tras un spraying, la clave de AWS
         que leyó un build... (solo con derive=True: construye el pack de cada candidata, ~30 s, y se cachea);
       - la tienda, para equipos de la zona STORES (la red de cada tienda es plana).
  3. Dos candidatas se unen si comparten una entidad y son de REGLAS DISTINTAS, a <= WINDOW_DAYS días si la entidad
     es una identidad (usuario, clave, fichero, cliente) o una tienda, y a <= 48 h si es infraestructura (equipo, IP, dominio).
     Una entidad en más de MAX_ENTITY_ALERTS candidatas no une (sería un hub entre las candidatas). Union-find.
  4. Un incidente es un grupo de >= 2 alertas de >= 2 reglas distintas: varias alertas de una sola regla son
     una repetición (lo agrupan los patrones), no una cadena.
Cada incidente explica por qué se unió (links: qué entidad, de dónde sale y qué alertas une).
"""
from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from core.config import CACHE_DIR, DB_PATH
from core.store import is_hub, norm_user, rows
from core.tools import local_time

NOISE_PATTERN_MIN = 30
WINDOW_DAYS = 21
MAX_ENTITY_ALERTS = 15
INFRA_TYPES = {"host", "ip", "domain"}   # infraestructura: une solo alertas cercanas en el tiempo
INFRA_WINDOW = timedelta(hours=48)
CACHE = CACHE_DIR / "incidents.json"

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]

# Tácticas MITRE del catálogo -> fase en castellano, en orden de cadena de ataque
PHASES = [
    ("Reconnaissance", "Reconocimiento"), ("Resource Development", "Preparación"),
    ("Initial Access", "Acceso inicial"), ("Execution", "Ejecución"), ("Persistence", "Persistencia"),
    ("Privilege Escalation", "Escalada de privilegios"), ("Defense Evasion", "Evasión de defensas"),
    ("Credential Access", "Robo de credenciales"), ("Discovery", "Descubrimiento"),
    ("Lateral Movement", "Movimiento lateral"), ("Collection", "Recopilación"),
    ("Command and Control", "Comando y control"), ("Exfiltration", "Exfiltración"), ("Impact", "Impacto"),
]
PHASE_ES = dict(PHASES)
PHASE_RANK = {es: i for i, (_, es) in enumerate(PHASES)}

NODE_TYPE = {"user": "user", "host": "host", "file": "file", "hash": "file", "access_key": "key",
             "customer": "customer", "session": "session", "message_id": "email", "site": "site"}

# Claves de los eventos de una comprobación que nombran una entidad (para las entidades descubiertas)
DERIVED_KEYS = {"cuenta": "user", "user": "user", "user_upn": "user", "actor_upn": "user", "usuario": "user",
                "identidad": "user", "hostname": "host", "equipo": "host", "customer_id": "customer"}


# ------------------------------------------------------------------ utilidades
def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _norm(value: Any, etype: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if etype == "user":
        v = norm_user(v) or ""
        return v if re.fullmatch(r"[a-z0-9][a-z0-9._\-]*", v) else None   # fuera "(161 cuentas)" y similares
    if etype == "host":
        return v.upper()
    return v


class _UF:
    def __init__(self, items: Iterable[str]):
        self.p = {x: x for x in items}

    def find(self, x: str) -> str:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


# ------------------------------------------------------------------ paso 1: candidatas
def candidates() -> tuple[dict[str, dict], dict[str, str]]:
    """Alertas que pueden formar parte de una cadena, y su patrón (pattern_id)."""
    from core.fingerprint import compute_patterns
    pattern_of, noise = {}, set()
    for p in compute_patterns():
        for aid in p["alert_ids"]:
            pattern_of[aid] = p["pattern_id"]
        if p["count"] >= NOISE_PATTERN_MIN and not p["is_outlier"]:
            noise.update(p["alert_ids"])
    alerts = {r["alert_id"]: r for r in rows(
        """SELECT a.alert_id, a.created_at, a.rule_id, a.rule_name, a.severity, a.runbook, c.tactica
           FROM alerts a LEFT JOIN catalogo c USING (rule_id)""") if r["alert_id"] not in noise}
    return alerts, pattern_of


# ------------------------------------------------------------------ paso 2: entidades
def alert_level_entities(ids: set[str]) -> dict[str, set[tuple[str, str, str]]]:
    """{alert_id: {(entity, etype, origen)}} de alert_entities, sin hubs ni campañas."""
    out: dict[str, set] = defaultdict(set)
    for r in rows("SELECT alert_id, entity, etype FROM alert_entities"):
        if r["alert_id"] in ids and not is_hub(r["entity"], include_campaigns=True):
            e = _norm(r["entity"], r["etype"]) if r["etype"] in ("user", "host") else r["entity"]
            if e:
                out[r["alert_id"]].add((e, r["etype"], "alerta"))
    return out


def site_entities(ents: dict[str, set]) -> None:
    """Añade la tienda a las alertas con equipos de la zona STORES (red plana por tienda)."""
    stores = {r["hostname"].upper(): r for r in rows("SELECT hostname, ip, location FROM activos WHERE zone = 'STORES'")}
    by_ip = {r["ip"]: r for r in stores.values() if r.get("ip")}
    for aid, es in ents.items():
        for e, et, _ in list(es):
            a = stores.get(e) if et == "host" else by_ip.get(e) if et == "ip" else None
            if a and (m := re.match(r"(Tienda \d+)", a.get("location") or "")):
                es.add((m.group(1), "site", f"inventario: {a['hostname']} está en {m.group(1)}"))


def derived_entities(ids: Iterable[str], ents: dict[str, set], verbose: bool = False) -> None:
    """Entidades que DESCUBREN las recetas o comparaciones que avisan (no vienen en la alerta)."""
    from core.context import build_pack
    for i, aid in enumerate(sorted(ids), 1):
        try:
            pack = build_pack(aid)
        except Exception:
            continue
        for c in pack.checks:
            if not c.attention:
                continue
            for ev in c.events:
                found = []
                for k, et in DERIVED_KEYS.items():
                    if k in ev:
                        found.append((_norm(ev[k], et), et))
                ui = ev.get("userIdentity")
                if isinstance(ui, str):          # los eventos compactos guardan los dict como JSON
                    try:
                        ui = json.loads(ui)
                    except ValueError:
                        ui = None
                if isinstance(ui, dict):
                    found += [(ui.get("accessKeyId"), "access_key"), (_norm(ui.get("userName"), "user"), "user")]
                for e, et in found:
                    if e and not is_hub(e, include_campaigns=True):
                        ents[aid].add((e, et, f"receta {c.id}"))
        if verbose and i % 50 == 0:
            print(f"  entidades descubiertas: {i} alertas", flush=True)


# ------------------------------------------------------------------ pasos 3 y 4: grafo e incidentes
def correlate(derive: bool = True, verbose: bool = False) -> list[dict]:
    alerts, pattern_of = candidates()
    ids = set(alerts)
    ents = alert_level_entities(ids)
    for aid in ids:
        ents.setdefault(aid, set())
    site_entities(ents)
    if derive:
        derived_entities(ids, ents, verbose)

    by_entity: dict[tuple[str, str], list[str]] = defaultdict(list)
    origin: dict[tuple[str, str], set[str]] = defaultdict(set)
    for aid, es in ents.items():
        for e, et, src in es:
            if aid not in by_entity[(e, et)]:
                by_entity[(e, et)].append(aid)
            origin[(e, et)].add(src)

    uf = _UF(ids)
    links: dict[tuple[str, str], list[str]] = {}
    for key, aids in by_entity.items():
        if len(aids) < 2 or len(aids) > MAX_ENTITY_ALERTS:
            continue
        aids.sort(key=lambda a: alerts[a]["created_at"])
        joined = set()
        # Una entidad solo une alertas de REGLAS DISTINTAS: diez builds de la misma regla en el mismo runner
        # son una repetición, no una cadena (las repeticiones las agrupa fingerprint.py)
        # La identidad (usuario, clave, fichero, cliente) une hasta WINDOW_DAYS: un atacante reutiliza la cuenta
        # robada días después. La infraestructura (equipo, IP, dominio, tienda) solo une alertas a <= 48 h: a un
        # servidor le llega actividad legítima de administración constantemente. Una tienda ("site") usa la ventana
        # larga: es un segmento pequeño y plano (un portátil y unos TPV) y quien entra en un equipo alcanza los demás
        window = INFRA_WINDOW if key[1] in INFRA_TYPES else timedelta(days=WINDOW_DAYS)
        for i, x in enumerate(aids):
            for y in aids[i + 1:]:
                if _ts(alerts[y]["created_at"]) - _ts(alerts[x]["created_at"]) > window:
                    break
                if alerts[x]["rule_id"] != alerts[y]["rule_id"]:
                    uf.union(x, y)
                    joined.update((x, y))
        if joined:
            links[key] = [a for a in aids if a in joined]

    groups: dict[str, list[str]] = defaultdict(list)
    for aid in ids:
        groups[uf.find(aid)].append(aid)
    incidents = []
    for members in groups.values():
        if len(members) < 2 or len({alerts[a]["rule_id"] for a in members}) < 2:
            continue
        members.sort(key=lambda a: alerts[a]["created_at"])
        incidents.append(_incident(members, alerts, ents, links, origin, pattern_of))
    incidents.sort(key=lambda i: i["first_seen"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-2026-{n:03d}"
    return incidents


def _incident(members, alerts, ents, links, origin, pattern_of) -> dict:
    mset = set(members)
    # Entidades del incidente y cuántas alertas toca cada una
    touch: Counter = Counter()
    for a in members:
        for e, et, _ in ents[a]:
            touch[(e, et)] += 1
    used_links = [{"entity": e, "type": et, "alerts": [a for a in aids if a in mset], "from": sorted(origin[(e, et)])}
                  for (e, et), aids in links.items() if len([a for a in aids if a in mset]) >= 2]
    used_links.sort(key=lambda l: -len(l["alerts"]))
    primary = next((e for (e, et), _ in touch.most_common() if et == "user"), None) or \
        next((e for (e, et), _ in touch.most_common() if et == "host"), None) or \
        (touch.most_common(1)[0][0][0] if touch else "")

    sev = max((alerts[a]["severity"] for a in members), key=lambda s: SEV_ORDER.index(s) if s in SEV_ORDER else 0)
    phases_seen = sorted({PHASE_ES.get(alerts[a]["tactica"] or "", alerts[a]["tactica"] or "Otra") for a in members},
                         key=lambda p: PHASE_RANK.get(p, 99))
    rules = Counter(alerts[a]["rule_id"] for a in members)
    first, last = alerts[members[0]]["created_at"], alerts[members[-1]]["created_at"]

    timeline = []
    for a in members:
        al = alerts[a]
        main = sorted((e for e, et, src in ents[a] if src == "alerta" and et in ("user", "host")))[:2]
        timeline.append({"ts": local_time(al["created_at"]), "phase": PHASE_ES.get(al["tactica"] or "", al["tactica"] or "Otra"),
                         "event": f"{al['rule_name']}" + (f" · {', '.join(main)}" if main else ""),
                         "alert_id": a, "rule_id": al["rule_id"], "severity": al["severity"]})

    nodes, edges = _graph(members, ents, alerts)
    return {
        "incident_id": "",
        "title": f"{' → '.join(phases_seen)} · {primary}",
        "severity": sev,
        "status": "investigating",
        "primary_entity": primary,
        "impact_summary": (f"{len(members)} alertas de {len(rules)} reglas entre {local_time(first)} y {local_time(last)}. "
                           f"Fases: {', '.join(phases_seen)}. Unidas por: "
                           + "; ".join(f"{l['entity']} ({len(l['alerts'])} alertas)" for l in used_links[:4]) + "."),
        "alerts": members,
        "rules": dict(rules),
        "first_seen": first,
        "last_seen": last,
        "patterns": sorted({pattern_of.get(a, "") for a in members} - {""}),
        "links": used_links,
        "timeline": timeline,
        "nodes": nodes,
        "edges": edges,
    }


def _graph(members: list[str], ents: dict[str, set], alerts: dict) -> tuple[list[dict], list[dict]]:
    """Nodos = entidades del incidente; aristas = entidades que aparecen juntas en una misma alerta."""
    mal = {r["value"].lower() for r in rows("SELECT value FROM ti_feed WHERE reputation = 'malicious'")}
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], str] = {}
    for a in members:
        here = []
        for e, et, src in sorted(ents[a]):
            if et == "ip" and re.match(r"^(10\.|172\.16\.|192\.168\.)", e):
                continue                                    # IPs internas: el equipo ya aparece como nodo
            ntype = NODE_TYPE.get(et) or ("c2" if e.lower() in mal else et)
            nid = f"{ntype}:{e}"
            nodes.setdefault(nid, {"id": nid, "label": e, "type": ntype, "derived": src != "alerta"})
            if src == "alerta":
                nodes[nid]["derived"] = False
            here.append(nid)
        for x in here:
            for y in here:
                if x < y and (x, y) not in edges:
                    edges[(x, y)] = alerts[a]["rule_name"]
    return list(nodes.values()), [{"source": s, "target": t, "label": lab} for (s, t), lab in edges.items()]


# ------------------------------------------------------------------ API para la consola
def compute_incidents(refresh: bool = False, derive: bool = True) -> list[dict]:
    """Incidentes con el formato de IncidentsView.vue. Cacheado en data/cache/incidents.json mientras la base no cambie."""
    stamp = DB_PATH.stat().st_mtime if DB_PATH.exists() else 0
    if not refresh and CACHE.exists():
        try:
            data = json.loads(CACHE.read_text(encoding="utf-8"))
            if data.get("db_mtime") == stamp and data.get("derive") == derive:
                return data["incidents"]
        except (ValueError, KeyError):
            pass
    incs = correlate(derive=derive)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps({"db_mtime": stamp, "derive": derive, "computed_at": datetime.now(timezone.utc).isoformat(),
                                 "incidents": incs}, ensure_ascii=False, default=str), encoding="utf-8")
    return incs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="sin entidades descubiertas por las recetas")
    args = ap.parse_args()
    t = time.time()
    incs = compute_incidents(refresh=True, derive=not args.fast)
    print(f"{len(incs)} incidentes en {time.time() - t:.0f} s (caché: {CACHE})\n")
    for i in incs:
        print(f"{i['incident_id']}  {i['severity']:<8} {len(i['alerts']):>3} alertas  {i['title']}")
        for l in i["links"][:4]:
            print(f"      unido por {l['type']} {l['entity']} ({len(l['alerts'])} alertas; {', '.join(l['from'])})")


if __name__ == "__main__":
    main()
