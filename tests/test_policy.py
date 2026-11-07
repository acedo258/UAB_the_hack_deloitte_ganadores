"""Tests de la política. Ejecutar: python -m pytest -q"""
from core.policy import approval_for, final_severity


def test_matriz_basica():
    assert final_severity("low", "Crítica")[0] == "medium"
    assert final_severity("high", "Alta")[0] == "high"
    assert final_severity("critical", "Baja")[0] == "high"
    assert final_severity("informational", "Media")[0] == "informational"


def test_ejemplo_oficial_waf():
    # ticket_ejemplo.json: regla low sobre activo crítico = medium; −1 por bloqueo del WAF
    sev, why = final_severity("low", "Crítica", down=True)
    assert sev == "low" and "−1" in why


def test_ajuste_maximo_un_nivel():
    assert final_severity("medium", "Media", up=True)[0] == "high"
    assert final_severity("medium", "Media", up=True, down=True)[0] == "medium"
    assert final_severity("critical", "Crítica", up=True)[0] == "critical"


def test_benign_y_fp():
    assert final_severity("high", "Crítica", verdict="benign_true_positive")[0] == "low"
    assert final_severity("low", "Media", verdict="benign_true_positive")[0] == "informational"
    assert final_severity("critical", "Crítica", verdict="false_positive")[0] == "informational"


def test_criticidad_desconocida_asume_media():
    sev, why = final_severity("high", None)
    assert sev == "high" and "desconocida" in why


def test_aprobaciones():
    assert approval_for("block_ioc", "aplihartom.com", []) == (False, "", "")
    assert approval_for("block_ioc", "mega.nz", [])[0] is True
    assert approval_for("revoke_sessions", "laura.ferrer2", [])[:2] == (True, "N2")
    pos = [{"hostname": "POS-T07-01", "zone": "STORES", "type": "TPV"}]
    assert approval_for("isolate_host", "POS-T07-01", pos)[1] == "N2 + negocio"
    plc = [{"hostname": "PLC-SORT01", "zone": "LOGISTICS-OT"}]
    assert approval_for("isolate_host", "PLC-SORT01", plc)[1] == "Responsable de Operaciones"
