"""Ingesta de alertas nuevas (core/ingest.py). Trabaja sobre una copia temporal de la base: la buena no se toca.
Ejecutar: python -m pytest -q"""
import json
import shutil

import pytest

from core import store
from core.config import DB_PATH

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def _alert(alert_id="ALR-20261108-990001", **over):
    a = store.rows("SELECT raw FROM alerts WHERE alert_id = 'ALR-20261009-011790'")[0]["raw"]
    a = json.loads(json.dumps(a))
    a.update({"alert_id": alert_id, "created_at": "2026-10-09T09:40:00.000Z", **over})
    return a


@pytest.fixture()
def db_copy(tmp_path, monkeypatch):
    """Copia de la base en una carpeta temporal; al acabar se vuelve a la original."""
    from core import ingest
    ingest._close_thread_connection()
    dst = tmp_path / "tarvia.duckdb"
    shutil.copy2(DB_PATH, dst)
    monkeypatch.setattr(store, "DB_PATH", dst)
    yield dst
    ingest._close_thread_connection()


def _write(tmp_path, alerts, extra_lines=()):
    f = tmp_path / "nuevas.jsonl"
    f.write_text("\n".join([json.dumps(a, ensure_ascii=False) for a in alerts] + list(extra_lines)) + "\n", encoding="utf-8")
    return f


def test_lee_jsonl_y_array(tmp_path):
    from core.ingest import read_alerts
    f = _write(tmp_path, [{"alert_id": "A"}], ['{"roto": '])
    alerts, rejected = read_alerts(f)
    assert [a["alert_id"] for a in alerts] == ["A"] and "línea 2" in rejected[0]["reason"]
    g = tmp_path / "array.json"
    g.write_text(json.dumps([{"alert_id": "A"}, {"alert_id": "B"}]), encoding="utf-8")
    assert len(read_alerts(g)[0]) == 2


def test_valida_y_completa_runbook():
    from core.ingest import validate
    cat = {r["rule_id"]: r for r in store.rows("SELECT rule_id, runbook FROM catalogo")}
    a = _alert()
    a.pop("runbook")
    assert validate(a, cat) is None and a["runbook"] == cat["UC-EML-002"]["runbook"]
    assert "faltan" in validate({"alert_id": "X", "severity": "high"}, cat)
    assert "severidad" in validate(_alert(severity="urgente"), cat)
    assert "fecha" in validate(_alert(created_at="ayer"), cat)


def test_dry_run_no_escribe(db_copy, tmp_path):
    from core.ingest import ingest_alerts
    before = db_copy.stat().st_mtime
    r = ingest_alerts(_write(tmp_path, [_alert()]), dry_run=True, correlate=False, verbose=False)
    assert r["new"] == ["ALR-20261108-990001"] and r["packs"][0]["chars"] > 0
    assert db_copy.stat().st_mtime == before
    assert not store.rows("SELECT 1 FROM alerts WHERE alert_id = 'ALR-20261108-990001'")


def test_ingesta_real_inserta_y_no_duplica(db_copy, tmp_path):
    from core.ingest import ingest_alerts
    f = _write(tmp_path, [_alert(), _alert()], [json.dumps(_alert("ALR-20261009-011790"))])
    r = ingest_alerts(f, correlate=False, verbose=False)
    assert r["new"] == ["ALR-20261108-990001"] and len(r["skipped"]) == 2   # repetida en el fichero + ya en la base
    assert r["backup"] and (db_copy.parent / "backups").exists()
    a = store.rows("SELECT dev_sample, raw FROM alerts WHERE alert_id = 'ALR-20261108-990001'")[0]
    assert a["dev_sample"] is False and a["raw"]["ingested_at"]
    ents = {e["entity"] for e in store.rows("SELECT entity FROM alert_entities WHERE alert_id = 'ALR-20261108-990001'")}
    assert "marta.puig" in ents
    assert not r["packs"][0].get("error") and r["packs"][0]["signals"] >= 1
    again = ingest_alerts(f, correlate=False, verbose=False)
    assert again["new"] == [] and again["backup"] is None                    # segunda vez: nada que hacer


def test_restaurar_copia(db_copy, tmp_path):
    from core.ingest import ingest_alerts, restore
    r = ingest_alerts(_write(tmp_path, [_alert()]), correlate=False, verbose=False)
    restore(__import__("pathlib").Path(r["backup"]))
    assert not store.rows("SELECT 1 FROM alerts WHERE alert_id = 'ALR-20261108-990001'")
