<template>
  <n-space vertical :size="16">
    <n-card size="small">
      <n-tabs type="line" animated>
        <!-- Pestaña 1: Decisiones Humanas -->
        <n-tab-pane name="decisions" tab="👤 Registro de Decisiones de Analistas (N2)">
          <n-space vertical :size="12">
            <n-space align="center" justify="space-between">
              <span class="muted">
                Registro inmutable de auditoría: decisiones tomadas por personas sobre el triaje de la IA.
              </span>
              <n-button secondary size="small" :loading="loadingDecisions" @click="loadDecisions">
                🔄 Recargar
              </n-button>
            </n-space>
            <n-data-table
              :columns="decisionColumns"
              :data="decisions"
              :loading="loadingDecisions"
              :pagination="{ pageSize: 15 }"
            />
          </n-space>
        </n-tab-pane>

        <!-- Pestaña 2: Log de Contención (Deloitte API) -->
        <n-tab-pane name="containment" tab="🛡️ Registro de Acciones de Contención">
          <n-space vertical :size="12">
            <n-space align="center" justify="space-between">
              <span class="muted">
                Acciones ejecutadas en infraestructura (aislamiento de red, revocación de sesiones, bloqueo de IOCs).
              </span>
              <n-button secondary size="small" :loading="loadingContainment" @click="loadContainment">
                🔄 Recargar
              </n-button>
            </n-space>
            <n-data-table
              :columns="containmentColumns"
              :data="containmentLog"
              :loading="loadingContainment"
              :pagination="{ pageSize: 15 }"
            />
          </n-space>
        </n-tab-pane>
      </n-tabs>
    </n-card>
  </n-space>
</template>

<script setup>
import { h, onMounted, ref } from 'vue'
import { NButton, NCard, NDataTable, NSpace, NTabPane, NTabs, NTag } from 'naive-ui'
import { api, VERDICT_LABEL } from '../api'

const decisions = ref([])
const containmentLog = ref([])
const loadingDecisions = ref(false)
const loadingContainment = ref(false)

async function loadDecisions() {
  loadingDecisions.value = true
  try {
    decisions.value = await api.decisions()
  } catch {
    decisions.value = []
  } finally {
    loadingDecisions.value = false
  }
}

async function loadContainment() {
  loadingContainment.value = true
  try {
    containmentLog.value = await api.containmentLog()
  } catch {
    containmentLog.value = []
  } finally {
    loadingContainment.value = false
  }
}

onMounted(() => {
  loadDecisions()
  loadContainment()
})

const tag = (text, type) => h(NTag, { size: 'small', type, bordered: false }, () => text)

const decisionColumns = [
  {
    title: 'Fecha y Hora (UTC)',
    key: 'ts',
    width: 170,
    render: (r) => h('span', { class: 'mono' }, r.ts?.slice(0, 19).replace('T', ' ')),
  },
  { title: 'Alerta / Patrón', key: 'alert_id', width: 180, render: (r) => h('span', { class: 'mono' }, r.alert_id) },
  {
    title: 'Decisión tomada',
    key: 'decision',
    width: 150,
    render: (r) => {
      const typeMap = { approve: 'success', correct: 'warning', escalate: 'error' }
      const labelMap = { approve: 'Aprobado', correct: 'Corregido', escalate: 'Escalado N3' }
      return tag(labelMap[r.decision] || r.decision, typeMap[r.decision] || 'default')
    },
  },
  { title: 'Analista responsable', key: 'analyst', width: 160, render: (r) => h('b', r.analyst) },
  {
    title: 'Alertas resueltas',
    key: 'alerts_covered',
    width: 130,
    render: (r) => h('span', { class: 'mono' }, `×${r.alerts_covered || 1}`),
  },
  {
    title: 'Veredicto asignado',
    key: 'verdict',
    render: (r) => {
      const v = r.verdict || r.ai_verdict
      return v ? tag(VERDICT_LABEL[v] || v, v === 'true_positive' ? 'error' : 'success') : ''
    },
  },
]

const containmentColumns = [
  {
    title: 'Fecha y Hora',
    key: 'timestamp',
    width: 170,
    render: (r) => h('span', { class: 'mono' }, (r.timestamp || r.ts || '')?.slice(0, 19).replace('T', ' ')),
  },
  {
    title: 'Acción ejecutada',
    key: 'action',
    width: 160,
    render: (r) => tag(r.action, 'error'),
  },
  { title: 'Objetivo (Target)', key: 'target', width: 180, render: (r) => h('span', { class: 'mono' }, r.target) },
  { title: 'Aprobado por', key: 'approver', width: 140, render: (r) => h('b', r.approver || 'Sistema') },
  { title: 'Ticket', key: 'ticket_id', width: 180, render: (r) => h('span', { class: 'mono' }, r.ticket_id) },
  { title: 'Justificación', key: 'justification', ellipsis: { tooltip: true } },
]
</script>

<style scoped>
.muted {
  color: #64748b;
  font-size: 13px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
</style>