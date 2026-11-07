<template>
  <n-space vertical :size="16">
    <n-space align="center">
      <n-switch v-model:value="filters.dev" @update:value="load" /> <span>Solo muestra de desarrollo (150)</span>
      <n-switch v-model:value="filters.outliers_only" @update:value="load" /> <span>Solo atípicos</span>
      <n-input v-model:value="filters.rule_id" placeholder="Regla (UC-EDR-001)" clearable style="width: 200px" @change="load" />
      <n-button @click="load">Recargar</n-button>
      <span class="muted">{{ total }} alertas</span>
    </n-space>
    <n-data-table :columns="columns" :data="items" :loading="loading" :pagination="{ pageSize: 25 }"
                  :row-props="(r) => ({ style: 'cursor:pointer', onClick: () => $router.push(`/alerta/${r.alert_id}`) })" />
  </n-space>
</template>

<script setup>
import { h, onMounted, reactive, ref } from 'vue'
import { NButton, NDataTable, NInput, NSpace, NSwitch, NTag } from 'naive-ui'
import { api, SEV_TYPE, VERDICT_LABEL } from '../api'

const filters = reactive({ dev: true, outliers_only: false, rule_id: '' })
const items = ref([]), total = ref(0), loading = ref(false)

async function load() {
  loading.value = true
  try {
    const r = await api.queue({ ...filters, limit: 2000 })
    items.value = r.items; total.value = r.total
  } finally { loading.value = false }
}
onMounted(load)

const tag = (text, type) => h(NTag, { size: 'small', type, bordered: false }, () => text)
const columns = [
  { title: 'Hora (UTC)', key: 'created_at', width: 150, render: (r) => r.created_at.slice(0, 16).replace('T', ' ') },
  { title: 'Regla', key: 'rule_id', width: 120 },
  { title: 'Qué saltó', key: 'rule_name', ellipsis: { tooltip: true } },
  { title: 'Sev. regla', key: 'severity', width: 100, render: (r) => tag(r.severity, SEV_TYPE[r.severity]) },
  { title: 'Patrón', key: 'pattern_count', width: 110,
    render: (r) => r.is_outlier ? tag('atípico', 'warning') : tag(`×${r.pattern_count}`, 'default') },
  { title: 'Veredicto IA', key: 'ticket', width: 190,
    render: (r) => r.ticket ? tag(VERDICT_LABEL[r.ticket.verdict], r.ticket.verdict === 'true_positive' ? 'error' : 'success') : tag('sin triar', 'default') },
  { title: 'Sev. final', key: 'final', width: 100, render: (r) => r.ticket ? tag(r.ticket.severity, SEV_TYPE[r.ticket.severity]) : '' },
  { title: 'Estado', key: 'status', width: 110,
    render: (r) => r.ticket ? (r.ticket.manipulation_attempt ? tag('manipulación', 'error') : tag(r.ticket.status, r.ticket.status === 'proposed' ? 'info' : 'success')) : '' },
]
</script>

<style scoped>.muted { color: #888; font-size: 13px; }</style>
