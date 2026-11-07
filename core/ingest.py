"""Ingesta de alertas nuevas en la base, sin reconstruirla (para las alertas del domingo).  Responsable: A (datos).

    python -m core.ingest alertas_nuevas.jsonl             # copia de seguridad, carga, verifica packs y correlaciona
    python -m core.ingest alertas_nuevas.jsonl --dry-run   # solo valida y prueba los packs, no escribe nada
    python -m core.ingest --backups                        # lista las copias de seguridad
    python -m core.ingest --restore data/backups/tarvia-20261108-101500.duckdb   # vuelve atrás

Qué hace con cada alerta:
  1. Valida: campos obligatorios, severidad conocida, fecha legible. Si falta "runbook", lo toma del catálogo.
     Una alerta que ya está en la base se salta; una mal formada se rechaza con el motivo. Ninguna rompe la carga.
  2. Antes de escribir guarda una copia de la base en data/backups/.
  3. Inserta en `alerts` (con raw.ingested_at, para que la consola pueda distinguir las nuevas) y sus entidades en
     `alert_entities`, con la misma normalización que el resto (store.alert_entities).
  4. Genera el pack de cada alerta nueva y comprueba tiempo, tamaño y errores.
  5. Recalcula la correlación (las cachés de incidentes e informes dependen de la fecha de la base, así que se
     invalidan solas) y dice a qué incidente se ha unido cada alerta nueva.

Limitaciones: los eventos de log NO se añaden. Si las alertas nuevas citan eventos que no están en 04_logs, el pack lo
indica (related_events vacíos) y la ingesta lo cuenta como aviso. Para añadir logs hay que reconstruir con
python -m core.store. DuckDB solo admite un proceso escribiendo: parad la API (uvicorn) mientras se ingiere.
"""
from __future__ import annotations

import argparse
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from core import store

REQUIRED = ("alert_id", "created_at", "rule_id", "rule_name", "severity")
SEVERITIES = ("informational", "low", "medium", "high", "critical")


def backup_dir() -> Path:
    return store.DB_PATH.parent / "backups"


def _close_thread_connection() -> None:
    """La conexión de lectura que guarda store.db() bloquearía la escritura: se cierra y se reabre después."""
    con = getattr(store._local, "con", None)
    if con is not None:
        con.close()
        store._local.con = None


# ------------------------------------------------------------------ lectura y validación
def read_alerts(path: Path) -> tuple[list[dict], list[dict]]:
    """Admite JSONL (una alerta por línea) o un array JSON. Devuelve (alertas, rechazos con motivo)."""
    text = path.read_text(encoding="utf-8").strip()
    raw: list = []
    rejected: list[dict] = []
    if text.startswith("["):
        try:
            raw = json.loads(text)
        except ValueError as e:
            return [], [{"line": 0, "reason": f"JSON inválido: {e}"}]
    else:
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                raw.append(json.loads(line))
            except ValueError as e:
                rejected.append({"line": n, "reason": f"línea {n}: JSON inválido ({e.msg})"})
    return [a for a in raw if isinstance(a, dict)], rejected


def validate(a: dict, catalog: dict[str, dict]) -> str | None:
    """Motivo de rechazo, o None si la alerta es válida. Completa runbook desde el catálogo si falta."""
    missing = [k for k in REQUIRED if not a.get(k)]
    if missing:
        return f"faltan campos obligatorios: {', '.join(missing)}"
    if a["severity"] not in SEVERITIES:
        return f"severidad desconocida: {a['severity']}"
    try:
        datetime.fromisoformat(str(a["created_at"]).replace("Z", "+00:00"))
    except ValueError:
        return f"fecha ilegible: {a['created_at']}"
    if not a.get("runbook") and a["rule_id"] in catalog:
        a["runbook"] = catalog[a["rule_id"]]["runbook"]
    a.setdefault("entities", {})
    a.setdefault("evidence", {})
    a.setdefault("related_events", [])
    a.setdefault("source_product", "")
    return None


# ------------------------------------------------------------------ copia de seguridad
def make_backup() -> Path:
    backup_dir().mkdir(parents=True, exist_ok=True)
    dst = backup_dir() / f"tarvia-{datetime.now():%Y%m%d-%H%M%S}.duckdb"
    _close_thread_connection()
    shutil.copy2(store.DB_PATH, dst)
    return dst


def restore(backup: Path) -> None:
    if not backup.exists():
        raise FileNotFoundError(backup)
    _close_thread_connection()
    shutil.copy2(backup, store.DB_PATH)


# ------------------------------------------------------------------ ingesta
def ingest_alerts(path: str | Path, dry_run: bool = False, backup: bool = True, correlate: bool = True,
                  verbose: bool = True) -> dict:
    t0 = time.time()
    path = Path(path)
    say = print if verbose else (lambda *a, **k: None)
    alerts, rejected = read_alerts(path)
    catalog = {r["rule_id"]: r for r in store.rows("SELECT rule_id, runbook FROM catalogo")}
    existing = {r["alert_id"] for r in store.rows("SELECT alert_id FROM alerts")}

    new, skipped, warnings = [], [], []
    seen: set[str] = set()
    for a in alerts:
        why = validate(a, catalog)
        if why:
            rejected.append({"alert_id": a.get("alert_id", "?"), "reason": why})
            continue
        if a["alert_id"] in existing or a["alert_id"] in seen:
            skipped.append(a["alert_id"])
            continue
        if a["rule_id"] not in catalog:
            warnings.append(f"{a['alert_id']}: regla {a['rule_id']} no está en el catálogo (sin runbook ni recetas)")
        seen.add(a["alert_id"])
        new.append(a)
    say(f"{path.name}: {len(new)} nuevas, {len(skipped)} ya existían, {len(rejected)} rechazadas")
    for r in rejected:
        say(f"  rechazada {r.get('alert_id', '')}: {r['reason']}".replace("rechazada : ", "rechazada: "))

    backup_path = None
    if new and not dry_run:
        if backup:
            backup_path = make_backup()
            say(f"copia de seguridad: {backup_path}")
        _close_thread_connection()
        now = datetime.now(timezone.utc).isoformat()
        try:
            con = duckdb.connect(str(store.DB_PATH))
        except duckdb.IOException as e:
            raise RuntimeError("No se puede escribir en la base: otro proceso la tiene abierta (¿la API con uvicorn?). "
                               "Paradla, ingerid y volved a arrancarla.") from e
        try:
            con.execute("BEGIN")
            for a in new:
                a["ingested_at"] = now
                con.execute("""INSERT INTO alerts VALUES (?, CAST(? AS TIMESTAMPTZ), ?, ?, ?, ?, ?, FALSE, CAST(? AS JSON))""",
                            [a["alert_id"], a["created_at"], a.get("source_product", ""), a["rule_id"], a["rule_name"],
                             a["severity"], a.get("runbook", ""), json.dumps(a, ensure_ascii=False)])
                ents = store.alert_entities(a)
                if ents:
                    con.executemany("INSERT INTO alert_entities VALUES (?, ?, ?)", [(a["alert_id"], e, t) for e, t in ents])
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        say(f"insertadas {len(new)} alertas")

    # Verificación del pack de cada alerta nueva (en dry-run se pasa la alerta directamente, sin escribirla)
    from core.config import PACK_MAX_CHARS
    from core.context import build_pack
    checks = []
    for a in new:
        t = time.time()
        try:
            p = build_pack(a["alert_id"], alert=a if dry_run else None)
            chars = len(json.dumps(p.model_dump(exclude={"trace"}), ensure_ascii=False, default=str))
            errs = [c.id for c in p.checks if c.answer.startswith("no se pudo")]
            missing_ev = len(a.get("related_events", [])) - len(p.related_events)
            row = {"alert_id": a["alert_id"], "rule_id": a["rule_id"], "ms": int((time.time() - t) * 1000), "chars": chars,
                   "signals": sum(c.attention for c in p.checks if c.id != "RESUMEN"), "errors": errs,
                   "missing_related_events": missing_ev, "resumen": p.checks[0].answer[:140] if p.checks else ""}
            if chars > PACK_MAX_CHARS:
                warnings.append(f"{a['alert_id']}: pack de {chars} caracteres (límite {PACK_MAX_CHARS})")
            if missing_ev:
                warnings.append(f"{a['alert_id']}: {missing_ev} related_events no están en los logs cargados")
        except Exception as e:  # una alerta rara no tumba la ingesta: se informa
            row = {"alert_id": a["alert_id"], "rule_id": a["rule_id"], "error": f"{type(e).__name__}: {e}"[:200]}
            warnings.append(f"{a['alert_id']}: no se pudo construir el pack ({row['error']})")
        checks.append(row)
        say(f"  {row['alert_id']} {row['rule_id']}: " + (row.get("error") or
            f"{row['ms']} ms, {row['chars']} caracteres, {row['signals']} señales · {row['resumen']}"))

    joined = {}
    if correlate and new and not dry_run:
        from core.correlate import compute_incidents
        say("recalculando la correlación (~30 s)…")
        ids = {a["alert_id"] for a in new}
        for inc in compute_incidents(refresh=True):
            for aid in ids & set(inc["alerts"]):
                joined[aid] = f"{inc['incident_id']} · {inc['title']}"
        for aid in sorted(ids):
            say(f"  {aid}: " + (f"se une a {joined[aid]}" if aid in joined else "no se une a ningún incidente"))

    for w in warnings:
        say(f"aviso: {w}")
    say(f"listo en {time.time() - t0:.0f} s" + (" (dry-run: no se ha escrito nada)" if dry_run else ""))
    return {"new": [a["alert_id"] for a in new], "skipped": skipped, "rejected": rejected, "warnings": warnings,
            "packs": checks, "incidents": joined, "backup": str(backup_path) if backup_path else None, "dry_run": dry_run}


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingesta de alertas nuevas")
    ap.add_argument("path", nargs="?", help="fichero JSONL o JSON con las alertas")
    ap.add_argument("--dry-run", action="store_true", help="valida y prueba los packs sin escribir")
    ap.add_argument("--no-backup", action="store_true")
    ap.add_argument("--no-correlate", action="store_true")
    ap.add_argument("--backups", action="store_true", help="lista las copias de seguridad")
    ap.add_argument("--restore", help="restaura una copia de seguridad")
    args = ap.parse_args()
    if args.backups:
        for b in sorted(backup_dir().glob("*.duckdb")):
            print(f"{b}  {b.stat().st_size / 1e6:.0f} MB")
        return
    if args.restore:
        restore(Path(args.restore))
        print(f"restaurada {args.restore} sobre {store.DB_PATH}")
        return
    if not args.path:
        ap.error("indica el fichero de alertas")
    ingest_alerts(args.path, dry_run=args.dry_run, backup=not args.no_backup, correlate=not args.no_correlate)


if __name__ == "__main__":
    main()
