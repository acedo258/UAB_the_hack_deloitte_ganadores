"""Política del SOC de Tarvia en código (politica_soc.md).  Responsable: D (criterio).

El LLM propone; esta capa DECIDE lo que es regla escrita:
  - severidad final (matriz + ajustes de ±1 como máximo en total),
  - escalado obligatorio (apartado 5),
  - qué acciones requieren aprobación y de quién (apartado 4), y OT nunca.
Si el LLM contradice la política, gana la política y queda anotado en policy_notes.
"""
from __future__ import annotations

import time
import uuid
from typing import Iterable

from core.schemas import (Affected, ContextPack, Enrichment, Escalation, LLMTriage, RecommendedAction, Ticket)

SEV = ["informational", "low", "medium", "high", "critical"]
CRIT = ["Baja", "Media", "Alta", "Crítica"]

# Matriz del apartado 2: MATRIX[regla][criticidad]
MATRIX = {
    "informational": ["informational", "informational", "low", "low"],
    "low":           ["informational", "low", "low", "medium"],
    "medium":        ["low", "medium", "medium", "high"],
    "high":          ["medium", "high", "high", "critical"],
    "critical":      ["high", "critical", "critical", "critical"],
}

# Apartado 4: acción -> (requiere aprobación, aprobador)
APPROVALS = {
    "purge_email":        (False, ""),
    "block_ioc":          (False, ""),
    "revoke_sessions":    (True, "N2"),
    "reset_password":     (True, "N2"),
    "isolate_host":       (True, "N2"),            # puesto; servidor/TPV/web se ajusta abajo
    "disable_user":       (True, "N2"),
    "disable_access_key": (True, "N2"),
    "close":              (False, ""),
    "escalate":           (False, ""),
    "monitor":            (False, ""),
    "notify":             (False, ""),
}
DUAL_USE = ("mega.nz", "anydesk", "wetransfer", "dropbox", "drive.google", "teamviewer")


def base_severity(rule_sev: str, criticality: str | None) -> str:
    crit = criticality if criticality in CRIT else "Media"
    return MATRIX[rule_sev][CRIT.index(crit)]


def final_severity(rule_sev: str, criticality: str | None, *, up: bool = False, down: bool = False,
                   verdict: str = "true_positive") -> tuple[str, str]:
    """Devuelve (severidad, explicación)."""
    crit = criticality if criticality in CRIT else "Media"
    base = base_severity(rule_sev, crit)
    why = f"Regla {rule_sev} × activo {crit} = {base}"
    if criticality not in CRIT:
        why += " (criticidad desconocida, se asume Media)"
    if verdict == "benign_true_positive":
        sev = "low" if SEV.index(base) >= SEV.index("high") else "informational"
        return sev, why + f"; actividad autorizada → {sev}"
    if verdict == "false_positive":
        return "informational", why + "; falso positivo → informational"
    delta = (1 if up else 0) - (1 if down else 0)     # máximo un nivel en total
    sev = SEV[max(0, min(len(SEV) - 1, SEV.index(base) + delta))]
    if delta > 0:
        why += f"; +1 (ejecución/acceso confirmado, identidad VIP/privilegiada o datos personales/pagos) → {sev}"
    elif delta < 0:
        why += f"; −1 (bloqueado sin efecto) → {sev}"
    elif up and down:
        why += "; +1 y −1 se compensan"
    return sev, why


def max_criticality(pack: ContextPack, llm_hint: str | None) -> str | None:
    """La criticidad del activo más crítico afectado según la CMDB; si no hay activos, la que estime el LLM."""
    found = [a.get("criticality") for a in pack.assets if a.get("criticality") in CRIT]
    if found:
        return max(found, key=CRIT.index)
    return llm_hint


def approval_for(action: str, target: str, assets: Iterable[dict]) -> tuple[bool, str, str]:
    """(requiere_aprobación, aprobador, nota)."""
    asset = next((a for a in assets if a.get("hostname", "").upper() == target.upper()), None)
    if asset and asset.get("zone") == "LOGISTICS-OT":
        return True, "Responsable de Operaciones", "OT: el SOC nunca actúa; solo escalar"
    req, who = APPROVALS.get(action, (True, "N2"))
    note = ""
    if action == "isolate_host" and asset:
        name, typ, zone = asset["hostname"].upper(), (asset.get("type") or "").lower(), asset.get("zone", "")
        if name.startswith("POS-") or name.startswith("WEB-") or zone == "DMZ":
            who, note = "N2 + negocio", "Impacto en ventas"
        elif "servidor" in typ or zone in ("DC-SERVERS", "AWS-PROD", "DEV"):
            who, note = "N2 + responsable del servicio", f"Servicio: {asset.get('business_service', '')}"
    if action == "block_ioc" and any(d in target.lower() for d in DUAL_USE):
        req, who, note = True, "N2", "Servicio legítimo de uso dual: no bloquear globalmente sin N2"
    if action == "disable_user" and target.lower().startswith("svc_"):
        note = "Cuenta de servicio: puede parar un proceso de negocio"
    return req, who, note


def apply_policy(llm: LLMTriage, pack: ContextPack, started: float | None = None) -> Ticket:
    a = pack.alert
    notes: list[str] = []
    verdict = llm.verdict
    if llm.authorized_activity and verdict == "true_positive":
        verdict = "benign_true_positive"
        notes.append("El LLM marcó actividad autorizada: veredicto → benign_true_positive")
    if verdict == "benign_true_positive" and not pack.matching_changes and not llm.authorization_ref:
        notes.append("AVISO: benign_true_positive sin cambio/flujo aprobado que lo respalde — revisar")

    user_flags = any(str(u.get("vip")) == "True" or str(u.get("privileged")) == "True" for u in pack.users)
    up = llm.execution_confirmed or llm.privileged_or_vip or user_flags or llm.personal_data_or_payments
    crit = max_criticality(pack, llm.asset_criticality)
    sev, why = final_severity(a["severity"], crit, up=up, down=llm.blocked_without_effect, verdict=verdict)
    if llm.manipulation_attempt and SEV.index(sev) < SEV.index("medium") and verdict == "true_positive":
        sev = "medium"
        why += "; contiene un intento de manipular al sistema de triaje → mínimo medium"
    if llm.severity_guess and llm.severity_guess != sev:
        notes.append(f"El LLM proponía {llm.severity_guess}; la matriz da {sev}")

    # Escalado obligatorio (apartado 5)
    reasons = []
    if verdict == "true_positive" and sev in ("high", "critical"):
        reasons.append(f"true_positive {sev}")
    if verdict == "true_positive" and llm.execution_confirmed:
        reasons.append("ejecución o acceso confirmado")
    if verdict == "true_positive" and llm.personal_data_or_payments:
        reasons.append("datos personales o pagos implicados (valorar DPO / Tesorería)")
    if llm.escalate and llm.escalation_reason:
        reasons.append(llm.escalation_reason)
    if verdict == "needs_more_info":
        reasons.append("el sistema no puede concluir: revisión humana")
    escalate = bool(reasons) and verdict in ("true_positive", "needs_more_info")
    to = ""
    if escalate:
        to = "N2 de guardia por teléfono + Responsable SOC + CISO" if sev == "critical" else \
             "N2 (misma jornada) + Responsable SOC" if sev == "high" else "N2"
    if llm.escalate and not escalate:
        notes.append("El LLM pedía escalar pero el veredicto no lo justifica según la política")

    actions = []
    for ra in llm.recommended_actions:
        req, who, note = approval_for(ra.action, ra.target, pack.assets)
        if req != ra.requires_approval:
            notes.append(f"{ra.action} sobre {ra.target}: aprobación corregida a {req} ({who or 'N1'})")
        just = ra.justification + (f" · {note}" if note else "")
        actions.append(RecommendedAction(action=ra.action, target=ra.target, requires_approval=req, approver=who, justification=just))
    if not actions:
        actions.append(RecommendedAction(action="escalate" if escalate else "close", target="ticket", requires_approval=False,
                                         justification="Acción por defecto según veredicto"))

    users = [u.get("upn", "") for u in pack.users]
    hosts = [x["hostname"] for x in pack.assets]
    services = sorted({x.get("business_service", "") for x in pack.assets if x.get("business_service")})
    customers = [c.get("customer_id") for c in (a.get("entities", {}).get("customers") or [])]

    return Ticket(
        ticket_id=f"TKT-{a['alert_id'][4:]}-{uuid.uuid4().hex[:4]}",
        alert_ids=[a["alert_id"]], title=llm.title, verdict=verdict, confidence=llm.confidence,
        severity=sev, severity_rationale=why,
        affected=Affected(users=users, hosts=hosts, business_services=services, customers=customers),
        summary=llm.summary, evidence=llm.evidence,
        enrichment=[Enrichment(indicator=i.indicator, type=i.type, source=i.source, result=i.result) for i in pack.intel],
        mitre=llm.mitre or ([a["mitre"]["technique_id"]] if a.get("mitre") else []),
        recommended_actions=actions, escalation=Escalation(escalate=escalate, to=to, reason="; ".join(reasons)),
        open_questions=llm.open_questions, triage_seconds=round(time.time() - started, 1) if started else 0,
        manipulation_attempt=llm.manipulation_attempt or any(u.suspicious for u in pack.untrusted_fields),
        manipulation_detail=llm.manipulation_detail or "; ".join(f"{u.path}: {u.reason}" for u in pack.untrusted_fields if u.suspicious),
        llm_severity=llm.severity_guess, policy_notes=notes,
    )
