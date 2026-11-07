<template>
  <n-space vertical :size="16">
    <n-space align="center" justify="space-between">
      <n-space align="center">
        <n-button text @click="$router.push('/')">← Cola</n-button>
        <h2 style="margin: 0">{{ id }}</h2>
        <n-tag v-if="alert" :type="SEV_TYPE[alert.severity]" :bordered="false">regla {{ alert.severity }}</n-tag>
        <n-tag v-if="alert?.pattern?.is_outlier" type="warning" :bordered="false">atípico</n-tag>
        <n-tag v-else-if="alert?.pattern" :bordered="false">patrón ×{{ alert.pattern.count }}</n-tag>
      </n-space>
      <n-space>
        <n-button type="primary" :loading="running" @click="run(false)">{{ ticket ? 'Volver a triar' : 'Triar con IA' }}</n-button>
        <n-button :loading="running" @click="run(true)">Investigar a fondo</n-button>
      </n-space>
    </n-space>

    <n-grid :cols="24" :x-gap="16">
      <!-- 1. La alerta tal cual -->
      <n-gi :span="7">
        <n-card title="La alerta (SIEM)" size="small">
          <template v-if="alert">
            <p><b>{{ alert.rule_name }}</b><br /><span class="muted">{{ alert.description }}</span></p>
            <p class="muted">{{ alert.created_at }} · {{ alert.source_product }} · {{ alert.runbook }}</p>
            <pre class="mono raw">{{ JSON.stringify({ entities: alert.entities, evidence: alert.evidence }, null, 2) }}</pre>
          </template>
        </n-card>
      </n-gi>

      <!-- 2. Qué consultó la IA -->
      <n-gi :span="7">
        <n-card title="Qué ha consultado la IA" size="small" class="ai">
          <n-empty v-if="!steps.length" description="Pulsa «Triar con IA» para verlo en directo" />
          <n-timeline v-else>
            <n-timeline-item v-for="s in steps" :key="s.step" :type="stepType(s)"
                             :title="`${s.tool}`" :content="s.result_summary" :time="s.ms ? `${s.ms} ms` : ''" />
          </n-timeline>
        </n-card>
      </n-gi>

      <!-- 3. Qué concluye y en qué se basa -->
      <n-gi :span="10">
        <n-card title="Conclusión de la IA" size="small" class="ai">
          <n-empty v-if="!ticket" description="Sin triar" />
          <template v-else>
            <n-alert v-if="ticket.manipulation_attempt" type="error" title="Intento de manipular al sistema de triaje" style="margin-bottom: 12px">
              {{ ticket.manipulation_detail }}
            </n-alert>
            <h3 style="margin-top: 0">{{ ticket.title }}</h3>
            <n-space>
              <n-tag :type="ticket.verdict === 'true_positive' ? 'error' : 'success'">{{ VERDICT_LABEL[ticket.verdict] }}</n-tag>
              <n-tag :type="SEV_TYPE[ticket.severity]">severidad {{ ticket.severity }}</n-tag>
              <n-tag>confianza {{ Math.round(ticket.confidence * 100) }} %</n-tag>
              <n-tag v-if="ticket.escalation.escalate" type="error">escalar → {{ ticket.escalation.to }}</n-tag>
            </n-space>
            <p>{{ ticket.summary }}</p>
            <p class="muted"><b>Severidad:</b> {{ ticket.severity_rationale }}</p>
            <n-alert v-for="n in ticket.policy_notes" :key="n" type="warning" :bordered="false" style="margin: 4px 0">Política: {{ n }}</n-alert>

            <n-divider title-placement="left">En qué se basa</n-divider>
            <div v-for="(e, i) in ticket.evidence" :key="i" class="ev">
              <n-button v-if="e.event_id && !e.event_id.startsWith('CHG')" text type="primary" class="mono" @click="openEvent(e.event_id)">{{ e.event_id }}</n-button>
              <span v-else class="mono">{{ e.event_id || e.source }}</span>
              — {{ e.finding }}
            </div>
            <div v-if="ticket.enrichment.length" style="margin-top: 8px">
              <div v-for="x in ticket.enrichment" :key="x.indicator" class="muted mono">{{ x.indicator }}: {{ x.result }}</div>
            </div>
            <template v-if="ticket.open_questions.length">
              <n-divider title-placement="left">Lo que no ha podido resolver</n-divider>
              <ul><li v-for="q in ticket.open_questions" :key="q">{{ q }}</li></ul>
            </template>
          </template>
        </n-card>
      </n-gi>
    </n-grid>

    <!-- 4. Lo que decide la persona -->
    <n-card v-if="ticket" title="Decisión del analista" size="small" class="human">
      <n-space vertical>
        <n-space align="center">
          <n-input v-model:value="analyst" placeholder="Tu nombre" style="width: 180px" />
          <n-button type="primary" @click="decide('approve')">Aprobar triaje</n-button>
          <n-button v-if="alert?.pattern && !alert.pattern.is_outlier && alert.pattern.count > 1" @click="decide('approve', true)">
            Aprobar el patrón entero ({{ alert.pattern.count }} alertas)
          </n-button>
          <n-button type="error" ghost @click="decide('escalate')">Escalar a N2</n-button>
          <n-select v-model:value="correction" :options="verdictOptions" placeholder="Corregir veredicto" style="width: 220px" />
          <n-button :disabled="!correction" @click="decide('correct')">Guardar corrección</n-button>
          <n-tag :bordered="false">estado: {{ ticket.status }}</n-tag>
        </n-space>
        <n-divider title-placement="left">Acciones propuestas</n-divider>
        <div v-for="(a, i) in ticket.recommended_actions" :key="i" class="action">
          <n-tag size="small" :type="a.requires_approval ? 'warning' : 'default'">{{ a.action }}</n-tag>
          <span class="mono">{{ a.target }}</span>
          <span class="muted">{{ a.justification }}</span>
          <n-tag v-if="a.requires_approval" size="small" type="warning" :bordered="false">aprueba: {{ a.approver }}</n-tag>
          <n-button v-if="containable(a)" size="small" :type="a.requires_approval ? 'warning' : 'default'" @click="execute(a)">
            {{ a.requires_approval ? 'Aprobar y ejecutar' : 'Ejecutar' }}
          </n-button>
        </div>
      </n-space>
    </n-card>

    <n-modal v-model:show="showEvent" preset="card" style="width: 760px" title="Evento original">
      <pre class="mono raw">{{ JSON.stringify(eventData, null, 2) }}</pre>
    </n-modal>
  </n-space>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { NAlert, NButton, NCard, NDivider, NEmpty, NGi, NGrid, NInput, NModal, NSelect, NSpace, NTag,
  NTimeline, NTimelineItem, useMessage } from 'naive-ui'
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
  running.value = true; steps.value = []; ticket.value = null
  api.triage(props.id, {
    deep, force: true,
    onStep: (s) => steps.value.push(s),
    onTicket: (t) => { ticket.value = t; running.value = false },
    onError: (e) => { msg.error(e); running.value = false },
  })
}
const stepType = (s) => ({ guardrail: s.result_summary.startsWith('⚠') ? 'error' : 'success', llm: 'info', policy: 'warning' }[s.kind] || 'default')

async function openEvent(id) {
  try { eventData.value = await api.event(id); showEvent.value = true } catch (e) { msg.error(`No encontrado: ${id}`) }
}
async function decide(decision, pattern = false) {
  if (!analyst.value) return msg.warning('Escribe tu nombre: la decisión queda registrada')
  await api.decide({ alert_id: props.id, decision, analyst: analyst.value, verdict: decision === 'correct' ? correction.value : null, apply_to_pattern: pattern })
  ticket.value = await api.ticket(props.id)
  msg.success(pattern ? `Patrón aprobado (${alert.value.pattern.count} alertas)` : 'Decisión registrada')
}
const containable = (a) => CONTAINMENT.includes(a.action)
async function execute(a) {
  if (a.requires_approval && !analyst.value) return msg.warning(`Esta acción la aprueba ${a.approver}: escribe tu nombre`)
  try {
    const r = await api.contain({ ticket_id: ticket.value.ticket_id, action: a.action, target: a.target, justification: a.justification, approver: analyst.value })
    msg.success(`${a.action} ${a.target}: ${r.result}${r.approval_token ? ` (${r.approval_token})` : ''}`)
  } catch (e) { msg.error(e.message) }
}
</script>

<style scoped>
.muted { color: #777; font-size: 13px; }
.raw { white-space: pre-wrap; word-break: break-all; max-height: 520px; overflow: auto; background: #fafafa; padding: 8px; border-radius: 6px; }
.ev { margin: 4px 0; font-size: 14px; }
.action { display: flex; align-items: center; gap: 10px; margin: 6px 0; flex-wrap: wrap; }
</style>
