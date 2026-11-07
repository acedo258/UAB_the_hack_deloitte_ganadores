"""Contratos entre las cuatro piezas. Si cambias algo aquí, avísalo al equipo.

- ContextPack: lo que A (datos) entrega a B (agente).
- Ticket:      lo que B entrega a D (política) y a C (consola). Sigue ticket_salida.schema.json.
- TraceStep:   cada paso del agente; la consola lo pinta como "qué consultó la IA".
"""
from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
Criticality = Literal["Baja", "Media", "Alta", "Crítica"]


# ---------------------------------------------------------------- traza
class TraceStep(BaseModel):
    step: int
    kind: Literal["context", "tool", "llm", "policy", "guardrail", "human"] = "tool"
    tool: str = ""                 # p. ej. "get_asset", "intel", "llm.triage"
    input: dict[str, Any] = {}
    result_summary: str = ""       # una línea legible para la consola
    ms: int = 0
    ts: str = ""


# ---------------------------------------------------------------- contexto (A -> B)
class UntrustedField(BaseModel):
    """Texto que puede haber escrito el atacante. El agente nunca lo obedece."""
    path: str                      # p. ej. "alert.evidence.email_body_excerpt"
    text: str
    suspicious: bool = False       # True si parece una instrucción dirigida a un sistema automático
    reason: str = ""


class IntelResult(BaseModel):
    indicator: str
    type: str                      # ip | domain | sha256 | url
    source: str                    # ti_feed | geoip_asn | sandbox
    result: str                    # resumen en una línea
    malicious: Optional[bool] = None   # None = desconocido (¡no es limpio!)


class Check(BaseModel):
    """Una comprobación del runbook resuelta por código (core/recipes.py). El agente la lee; no decide nada."""
    id: str                        # p. ej. "RB-01.clics"
    question: str                  # la comprobación del runbook
    answer: str                    # el hecho en una línea (recuentos, primera vez...)
    attention: bool = False        # True = dato anómalo según una regla simple; NO es un veredicto
    count: Optional[int] = None
    events: list[dict[str, Any]] = []   # pocos eventos de apoyo, con event_id para citarlos


class ContextPack(BaseModel):
    alert: dict[str, Any]
    entities: dict[str, Any] = {}                # entidades de la alerta
    runbook_id: str = ""
    rule_info: dict[str, Any] = {}               # fila del catálogo de casos de uso
    local_time: str = ""                         # hora de España de la alerta
    assets: list[dict[str, Any]] = []            # CMDB de los hosts implicados (con vulnerabilidades)
    users: list[dict[str, Any]] = []             # directorio + eventos de RRHH
    matching_changes: list[dict[str, Any]] = []  # cambios/flujos aprobados que encajan
    intel: list[IntelResult] = []
    related_events: list[dict[str, Any]] = []    # los de alert.related_events
    timeline: list[dict[str, Any]] = []          # otros eventos de las entidades en ±24 h (resumidos)
    other_alerts: list[dict[str, Any]] = []      # otras alertas de las mismas entidades
    checks: list[Check] = []                     # comprobaciones del runbook ya resueltas (recetas)
    untrusted_fields: list[UntrustedField] = []
    notes: list[str] = []                        # avisos del constructor (truncados, no encontrados...)
    trace: list[TraceStep] = []


# ---------------------------------------------------------------- ticket (B -> D -> C)
class Evidence(BaseModel):
    source: str
    event_id: str = ""
    finding: str


class Enrichment(BaseModel):
    indicator: str
    type: str
    source: str
    result: str


class RecommendedAction(BaseModel):
    action: str                    # close | escalate | block_ioc | purge_email | isolate_host | ...
    target: str
    requires_approval: bool
    approver: str = ""             # lo rellena la política (N2, N2 + negocio...)
    justification: str = ""


class Escalation(BaseModel):
    escalate: bool
    to: str = ""
    reason: str = ""


class Affected(BaseModel):
    users: list[str] = []
    hosts: list[str] = []
    business_services: list[str] = []
    customers: list[str] = []


class Ticket(BaseModel):
    ticket_id: str
    alert_ids: list[str]
    title: str = Field(description="Qué pasa, no qué regla saltó")
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    severity_rationale: str = ""
    affected: Affected = Affected()
    summary: str
    evidence: list[Evidence]
    enrichment: list[Enrichment] = []
    mitre: list[str] = []
    recommended_actions: list[RecommendedAction]
    executed_actions: list[dict[str, Any]] = []
    escalation: Escalation
    open_questions: list[str] = []
    triage_seconds: float = 0
    # --- extensiones nuestras (no están en el esquema oficial; no molestan) ---
    manipulation_attempt: bool = False
    manipulation_detail: str = ""
    llm_severity: Optional[Severity] = None     # lo que propuso el LLM antes de aplicar la política
    policy_notes: list[str] = []                # qué corrigió la política y por qué
    pattern_id: str = ""
    status: Literal["proposed", "approved", "corrected", "escalated"] = "proposed"
    trace: list[TraceStep] = []


# ---------------------------------------------------------------- salida que pedimos al LLM
class LLMTriage(BaseModel):
    """Lo que devuelve el LLM. La severidad final y las aprobaciones las pone policy.py."""
    title: str
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    summary: str
    evidence: list[Evidence]
    mitre: list[str] = []
    asset_criticality: Optional[Criticality] = None   # la del activo/identidad más crítico
    execution_confirmed: bool = False      # +1 en la matriz
    privileged_or_vip: bool = False        # +1
    personal_data_or_payments: bool = False  # +1
    blocked_without_effect: bool = False   # -1
    authorized_activity: bool = False      # cambio o flujo aprobado -> benign
    authorization_ref: str = ""            # p. ej. CHG-2026-1031
    recommended_actions: list[RecommendedAction] = []
    escalate: bool = False
    escalation_reason: str = ""
    open_questions: list[str] = []
    manipulation_attempt: bool = False
    manipulation_detail: str = ""
    severity_guess: Optional[Severity] = None
