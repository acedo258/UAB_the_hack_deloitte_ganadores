<template>
  <n-space vertical :size="16">
    <!-- Barra superior -->
    <n-space align="center" justify="space-between" class="top-bar">
      <n-space align="center" :size="12">
        <n-button secondary size="small" @click="$router.push('/')">← Volver a Cola</n-button>
        <h2 style="margin: 0; font-family: monospace;">{{ id }}</h2>
        <n-tag v-if="alert" :type="SEV_TYPE[alert.severity]" :bordered="false" size="medium">
          Regla SIEM: {{ alert.severity?.toUpperCase() }}
        </n-tag>
        <n-tag v-if="alert?.pattern?.is_outlier" type="warning" :bordered="false" size="medium">
          ⚠️ Atípico (investigar a fondo)
        </n-tag>
        <n-tag v-else-if="alert?.pattern" :bordered="false" size="medium">
          🔁 Patrón común (×{{ alert.pattern.count }} alertas)
        </n-tag>
      </n-space>
      <n-space :size="12">
        <n-button type="primary" :loading="running" @click="run(false)">
          {{ ticket ? '🔄 Re-triar alerta' : '⚡ Triar con IA (N1 rápido)' }}
        </n-button>
        <n-button :loading="running" secondary type="info" @click="run(true)">
          🔍 Investigar a fondo (Modo Agéntico)
        </n-button>
      </n-space>
    </n-space>

    <!-- Alerta crítica de manipulación / prompt injection -->
    <n-alert
      v-if="ticket?.manipulation_attempt"
      type="error"
      title="🚨 INTENTO DE MANIPULACIÓN DETECTADO (PROMPT INJECTION / EVASIÓN)"
      style="border: 2px solid #d03050; box-shadow: 0 4px 12px rgba(208, 48, 80, 0.15);"
    >
      <p style="margin: 4px 0 8px 0; font-weight: 500;">
        El contenido no fiable analizado (correo, descripción o servicio) contiene un vector de evasión intentando engañar al triaje automático.
      </p>
      <div class="manipulation-box mono">
        <b>Detalle técnico:</b> {{ ticket.manipulation_detail || 'Intento de forzar veredicto falso positivo detectado y neutralizado.' }}
      </div>
      <p style="margin: 8px 0 0 0; font-size: 13px; color: #a02030;">
        🛡️ <b>Defensa activa:</b> El agente ha aislado el texto no fiable, preservando la severidad real y marcando manipulación para auditoría.
      </p>
    </n-alert>

    <!-- Grid principal de 3 columnas -->
    <n-grid :cols="24" :x-gap="16" :y-gap="16">
      <!-- 1. La alerta tal cual (SIEM) -->
      <n-gi :span="7">
        <n-card size="small" class="panel-card panel-siem">
          <template #header>
            <div class="card-header-flex">
              <span>🚨 Alerta original (SIEM)</span>
              <n-tag size="tiny" :bordered="false">Origen</n-tag>
            </div>
          </template>

          <template v-if="alert">
            <div class="siem-summary">
              <h4 style="margin: 0 0 4px 0;">{{ alert.rule_name }}</h4>
              <p class="muted" style="margin: 0 0 8px 0;">{{ alert.description }}</p>
              <div class="meta-row">
                <span>📅 {{ alert.created_at?.slice(0, 19).replace('T', ' ') }}</span>
                <span>📦 {{ alert.source_product }}</span>
                <span>📘 {{ alert.runbook }}</span>
              </div>
            </div>

            <n-divider style="margin: 12px 0 8px 0;" title-placement="left">Entidades afectadas</n-divider>
            <div class="entities-list">
              <div v-for="(val, key) in (alert.entities || {})" :key="key" class="entity-item">
                <span class="entity-key">{{ key }}:</span>
                <span class="mono entity-val">{{ Array.isArray(val) ? val.join(', ') : val }}</span>
              </div>
            </div>

            <n-collapse style="margin-top: 12px;">
              <n-collapse-item title="Ver JSON en crudo (SIEM)">
                <pre class="mono raw">{{ JSON.stringify({ entities: alert.entities, evidence: alert.evidence }, null, 2) }}</pre>
              </n-collapse-item>
            </n-collapse>
          </template>
        </n-card>
      </n-gi>

      <!-- 2. Qué consultó la IA -->
      <n-gi :span="7">
        <n-card size="small" class="panel-card panel-ai">
          <template #header>
            <div class="card-header-flex">
              <span>🤖 Traza del Agente (N1)</span>
              <n-tag type="info" size="tiny" :bordered="false">IA Autónoma</n-tag>
            </div>
          </template>

          <n-empty v-if="!steps.length" description="Pulsa «Triar con IA» para ver el razonamiento en directo" style="margin: 40px 0;" />
          <n-timeline v-else style="margin-top: 8px;">
            <n-timeline-item
              v-for="s in steps"
              :key="s.step"
              :type="stepType(s)"
              :title="`${s.tool}`"
              :content="s.result_summary"
              :time="s.ms ? `${s.ms} ms` : ''"
            />
          </n-timeline>
        </n-card>
      </n-gi>

      <!-- 3. Qué concluye y en qué se basa -->
      <n-gi :span="10">
        <n-card size="small" class="panel-card panel-ai">
          <template #header>
            <div class="card-header-flex">
              <span>💡 Propuesta de la IA</span>
              <n-tag type="info" size="tiny" :bordered="false">Recomendación N1</n-tag>
            </div>
          </template>

          <n-empty v-if="!ticket" description="Alerta pendiente de triar" style="margin: 40px 0;" />
          <template v-else>
            <h3 style="margin: 0 0 8px 0;">{{ ticket.title }}</h3>
            
            <n-space :size="8" style="margin-bottom: 12px;">
              <n-tag :type="ticket.verdict === 'true_positive' ? 'error' : (ticket.verdict === 'false_positive' ? 'success' : 'warning')" size="medium">
                Veredicto: {{ VERDICT_LABEL[ticket.verdict] || ticket.verdict }}
              </n-tag>
              <n-tag :type="SEV_TYPE[ticket.severity]" size="medium">
                Severidad final: {{ ticket.severity?.toUpperCase() }}
              </n-tag>
              <n-tag size="medium">
                Confianza: {{ Math.round((ticket.confidence || 0) * 100) }} %
              </n-tag>
              <n-tag v-if="ticket.escalation?.escalate" type="error" size="medium">
                ⚠️ Escalar → {{ ticket.escalation.to }}
              </n-tag>
            </n-space>

            <p style="margin: 0 0 12px 0; line-height: 1.5;">{{ ticket.summary }}</p>

            <!-- Desglose de Severidad y Políticas -->
            <div class="severity-breakdown">
              <div class="breakdown-title">⚖️ Explicabilidad y Motor de Política</div>
              <div class="breakdown-content">
                <div><b>Razón técnica:</b> {{ ticket.severity_rationale }}</div>
                <div v-if="ticket.policy_notes?.length" style="margin-top: 6px;">
                  <n-tag v-for="n in ticket.policy_notes" :key="n" type="warning" size="small" style="margin: 2px 4px 2px 0;">
                    Regla de política: {{ n }}
                  </n-tag>
                </div>
              </div>
            </div>

            <n-divider title-placement="left" style="margin: 12px 0 8px 0;">Evidencias verificadas (clic para ver evento)</n-divider>
            <div class="evidences-box">
              <div v-for="(e, i) in ticket.evidence" :key="i" class="ev-row">
                <n-button v-if="e.event_id && !e.event_id.startsWith('CHG')" size="tiny" secondary type="primary" class="mono" @click="openEvent(e.event_id)">
                  🔍 {{ e.event_id }}
                </n-button>
                <span v-else class="mono event-badge">{{ e.event_id || e.source }}</span>
                <span class="ev-finding">{{ e.finding }}</span>
              </div>
            </div>

            <!-- Dudas abiertas para el analista N2 -->
            <div v-if="ticket.open_questions?.length" class="open-questions-box">
              <div class="oq-title">❓ Lo que la IA no ha podido resolver (atención N2):</div>
              <ul style="margin: 4px 0 0 18px; padding: 0;">
                <li v-for="q in ticket.open_questions" :key="q">{{ q }}</li>
              </ul>
            </div>
          </template>
        </n-card>
      </n-gi>
    </n-grid>

    <!-- 4. Lo que decide la persona (N2) -->
    <n-card v-if="ticket" size="small" class="panel-card panel-human">
      <template #header>
        <div class="card-header-flex">
          <span style="color: #0F6E56; font-weight: 600;">👤 Decisión Humana (Analista N2)</span>
          <n-tag type="success" size="tiny" :bordered="false">Supervisión vinculante</n-tag>
        </div>
      </template>

      <n-space vertical :size="14">
        <n-space align="center" justify="space-between" style="background: #eef8f5; padding: 12px 16px; border-radius: 8px;">
          <n-space align="center" :size="10">
            <span style="font-weight: 500;">Analista responsable:</span>
            <n-input v-model:value="analyst" placeholder="Escribe tu nombre / alias" style="width: 200px" />
            <n-button type="primary" @click="decide('approve')">
              ✅ Aprobar triaje propuesto
            </n-button>
            <n-button v-if="alert?.pattern && !alert.pattern.is_outlier && alert.pattern.count > 1" secondary type="primary" @click="decide('approve', true)">
              🔁 Aprobar patrón completo ({{ alert.pattern.count }} alertas)
            </n-button>
            <n-button type="error" ghost @click="decide('escalate')">
              🚨 Escalar a N3 / Incident Response
            </n-button>
          </n-space>

          <n-space align="center" :size="10">
            <n-select v-model:value="correction" :options="verdictOptions" placeholder="Corregir veredicto" style="width: 200px" />
            <n-button :disabled="!correction" secondary type="warning" @click="decide('correct')">
              Guardar corrección
            </n-button>
            <n-tag size="small" :bordered="false" type="info">Estado actual: {{ ticket.status?.toUpperCase() }}</n-tag>
          </n-space>
        </n-space>

        <!-- Acciones propuestas y contención -->
        <div>
          <h4 style="margin: 0 0 8px 0;">Acciones de respuesta recomendadas:</h4>
          <div v-if="!ticket.recommended_actions?.length" class="muted">
            No se requieren acciones de contención activas para esta alerta.
          </div>
          <div v-for="(a, i) in ticket.recommended_actions" :key="i" class="action-card">
            <div class="action-left">
              <n-tag size="small" :type="a.requires_approval ? 'warning' : 'default'">{{ a.action }}</n-tag>
              <span class="mono" style="font-weight: 600;">{{ a.target }}</span>
              <span class="muted">{{ a.justification }}</span>
            </div>
            <div class="action-right">
              <n-tag v-if="a.requires_approval" size="small" type="warning" :bordered="false">
                Aprobación requerida por: {{ a.approver || 'Líder SOC' }}
              </n-tag>
              <n-button
                v-if="containable(a)"
                size="small"
                :type="a.requires_approval ? 'warning' : 'primary'"
                @click="execute(a)"
              >
                {{ a.requires_approval ? '🔐 Autorizar y ejecutar' : '⚡ Ejecutar contención' }}
              </n-button>
            </div>
          </div>
        </div>
      </n-space>
    </n-card>

    <!-- Modal para inspeccionar evento en crudo -->
    <n-modal v-model:show="showEvent" preset="card" style="width: 820px" title="🔎 Evento original en crudo (DuckDB)">
      <div v-if="eventData">
        <n-space align="center" style="margin-bottom: 8px;">
          <n-tag type="info" size="small">Fuente: {{ eventData.source }}</n-tag>
          <n-tag v-if="eventData.event_id" size="small" class="mono">{{ eventData.event_id }}</n-tag>
        </n-space>
        <pre class="mono raw">{{ JSON.stringify(eventData, null, 2) }}</pre>
      </div>
    </n-modal>
  </n-space>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import {
  NAlert, NButton, NCard, NCollapse, NCollapseItem, NDivider, NEmpty, NGi, NGrid, NInput,
  NModal, NSelect, NSpace, NTag, NTimeline, NTimelineItem, useMessage
} from 'naive-ui'
import { api, SEV_TYPE, VERDICT_LABEL } from '../api'

const props = defineProps({ id: String })
const msg = useMessage()
const alert = ref(null), ticket = ref(null), steps = ref([]), running = ref(false)
const analyst = ref(''), correction = ref(null), showEvent = ref(false), eventData = ref(null)
const verdictOptions = Object.entries(VERDICT_LABEL).map(([value, label]) => ({ value, label }))
const CONTAINMENT = ['isolate_host', 'disable_user', 'revoke_sessions', 'reset_password', 'block_ioc', 'purge_email', 'disable_access_key']

onMounted(async () => {
  alert.value = await api.alert(props.id)
  ticket.value = await api.ticket(props.id)
  steps.value = ticket.value?.trace || []
})

function run(deep) {
  running.value = true
  steps.value = []
  ticket.value = null
  api.triage(props.id, {
    deep,
    force: true,
    onStep: (s) => steps.value.push(s),
    onTicket: (t) => { ticket.value = t; running.value = false },
    onError: (e) => { msg.error(e); running.value = false },
  })
}

const stepType = (s) => ({
  guardrail: s.result_summary?.startsWith('⚠') ? 'error' : 'success',
  llm: 'info',
  policy: 'warning'
}[s.kind] || 'default')

async function openEvent(id) {
  try {
    eventData.value = await api.event(id)
    showEvent.value = true
  } catch (e) {
    msg.error(`No encontrado: ${id}`)
  }
}

async function decide(decision, pattern = false) {
  if (!analyst.value) return msg.warning('Escribe tu nombre: la decisión queda registrada para auditoría')
  await api.decide({
    alert_id: props.id,
    decision,
    analyst: analyst.value,
    verdict: decision === 'correct' ? correction.value : null,
    apply_to_pattern: pattern
  })
  ticket.value = await api.ticket(props.id)
  msg.success(pattern ? `Patrón aprobado (${alert.value.pattern.count} alertas)` : 'Decisión registrada')
}

const containable = (a) => CONTAINMENT.includes(a.action)

async function execute(a) {
  if (a.requires_approval && !analyst.value) return msg.warning(`Esta acción la aprueba ${a.approver}: escribe tu nombre`)
  try {
    const r = await api.contain({
      ticket_id: ticket.value.ticket_id,
      action: a.action,
      target: a.target,
      justification: a.justification,
      approver: analyst.value
    })
    msg.success(`${a.action} ${a.target}: ${r.result}${r.approval_token ? ` (${r.approval_token})` : ''}`)
  } catch (e) {
    msg.error(e.message)
  }
}
</script>

<style scoped>
.top-bar {
  background: #ffffff;
  padding: 12px 18px;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}
.panel-card {
  height: 100%;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}
.panel-siem {
  border-top: 3px solid #64748b;
}
.panel-ai {
  border-top: 3px solid #7F77DD;
}
.panel-human {
  border-top: 3px solid #1D9E75;
}
.card-header-flex {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}
.muted {
  color: #64748b;
  font-size: 13px;
}
.meta-row {
  display: flex;
  gap: 12px;
  font-size: 12px;
  color: #64748b;
  margin-top: 6px;
  flex-wrap: wrap;
}
.entities-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.entity-item {
  display: flex;
  font-size: 12px;
  gap: 6px;
}
.entity-key {
  font-weight: 600;
  color: #475569;
  min-width: 80px;
}
.entity-val {
  color: #0f172a;
  word-break: break-all;
}
.raw {
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 500px;
  overflow: auto;
  background: #f8fafc;
  padding: 10px;
  border-radius: 6px;
  border: 1px solid #e2e8f0;
}
.manipulation-box {
  background: #fff5f5;
  padding: 8px 12px;
  border-radius: 6px;
  border: 1px dashed #e53e3e;
  font-size: 13px;
}
.severity-breakdown {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 10px 12px;
  margin-bottom: 12px;
}
.breakdown-title {
  font-weight: 600;
  font-size: 13px;
  color: #334155;
  margin-bottom: 4px;
}
.breakdown-content {
  font-size: 13px;
  color: #475569;
}
.evidences-box {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.ev-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}
.event-badge {
  background: #f1f5f9;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
}
.ev-finding {
  color: #1e293b;
}
.open-questions-box {
  margin-top: 14px;
  background: #fffbeb;
  border-left: 3px solid #f59e0b;
  padding: 8px 12px;
  border-radius: 4px;
  font-size: 13px;
  color: #92400e;
}
.oq-title {
  font-weight: 600;
}
.action-card {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: #f8fafc;
  padding: 10px 14px;
  border-radius: 6px;
  border: 1px solid #e2e8f0;
  margin-top: 8px;
}
.action-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.action-right {
  display: flex;
  align-items: center;
  gap: 8px;
}
</style>