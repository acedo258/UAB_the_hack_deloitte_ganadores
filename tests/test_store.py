"""Enlaces entre fuentes que dependen de ENTITY_MAP (core/store.py). Ejecutar: python -m pytest -q"""
import pytest

from core.config import DB_PATH
from core.store import alert_entities, norm_user, url_domain

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def _sources(entity, etype):
    from core.store import rows
    return {r["source"] for r in rows(
        "SELECT DISTINCT source FROM entity_events WHERE entity = ? AND etype = ?", [entity, etype])}


def test_adjunto_correo_enlaza_con_ejecucion_edr():
    # El sha256 del EDR es el de wscript.exe: el enlace correo -> ejecución va por nombre de fichero
    assert {"email", "edr_events"} <= _sources("pedido_q4_2026.js", "file")


def test_alertas_correo_y_edr_comparten_fichero():
    from core.store import rows
    rules = {r["rule_id"] for r in rows(
        "SELECT DISTINCT a.rule_id FROM alert_entities x JOIN alerts a USING (alert_id) "
        "WHERE x.etype = 'file' AND x.entity = 'pedido_q4_2026.js'")}
    assert {"UC-EML-002", "UC-EDR-001"} <= rules


def test_cloudtrail_usuario_creado():
    # svc_ecom_deploy crea backup-sync: el usuario creado tiene que ser entidad
    assert "cloudtrail" in _sources("backup-sync", "user")


def test_cliente_victima_en_tool_calls_de_vela():
    from core.store import rows
    n = rows("SELECT count(*) AS n FROM entity_events WHERE source = 'ai_gateway' AND etype = 'customer'")[0]["n"]
    sessions = rows("SELECT count(*) AS n FROM ai_gateway WHERE customer_id IS NOT NULL")[0]["n"]
    assert n > sessions        # hay clientes que solo aparecen dentro de tool_calls


def test_idp_audit_target_usuario_y_app():
    assert "idp_audit" in _sources("laura.ferrer2", "user")
    assert "idp_audit" in _sources("Miro", "app")


def test_dominios_de_urls():
    assert {"email", "email_clicks"} <= _sources("retailforum.example", "domain")


def test_helpers_python_igual_que_sql():
    assert norm_user("TARVIA\\Marta.Puig") == "marta.puig"
    assert url_domain("https://WWW.Tarvia.example/.env") == "www.tarvia.example"
    ents = alert_entities({"entities": {"files": [{"name": "A.JS", "sha256": "AB"}], "urls": ["http://x.example/a"]}})
    assert ("a.js", "file") in ents and ("ab", "hash") in ents and ("x.example", "domain") in ents
