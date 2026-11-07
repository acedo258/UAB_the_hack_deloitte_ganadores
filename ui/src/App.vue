<template>
  <n-config-provider :theme-overrides="theme">
    <n-message-provider>
      <n-layout style="min-height: 100vh">
        <n-layout-header bordered class="header">
          <div class="brand">
            <span style="color: #0F6E56; font-size: 18px;">🛡️ SOC N1 · Tarvia</span>
            <span class="sub">Triaje de ciberseguridad asistido por IA</span>
          </div>

          <n-menu
            mode="horizontal"
            :options="menu"
            :value="$route.path"
            @update:value="(k) => $router.push(k)"
            style="margin-left: 12px;"
          />

          <div v-if="stats.data" class="funnel">
            <span class="funnel-pill"><b>{{ fmt(stats.data.alerts) }}</b> alertas SIEM</span>
            <span class="arrow">→</span>
            <span class="funnel-pill"><b>{{ stats.data.patterns }}</b> patrones</span>
            <span class="arrow">→</span>
            <span class="funnel-pill" style="color: #b45309;"><b>{{ stats.data.outliers }}</b> atípicos</span>
            <span class="arrow">→</span>
            <span class="funnel-pill-success">
              ⏱️ <b>{{ Math.round((stats.data.minutes_saved || (stats.data.triaged * 15)) / 60) }}h</b> ahorradas
            </span>
          </div>

          <n-button
            type="primary"
            secondary
            size="small"
            style="margin-left: 12px; font-weight: 600;"
            @click="triggerDemoMode"
          >
            ▶️ Modo Demo
          </n-button>
        </n-layout-header>

        <n-layout-content content-style="padding: 20px 24px">
          <router-view />
        </n-layout-content>
      </n-layout>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { NButton, NConfigProvider, NLayout, NLayoutContent, NLayoutHeader, NMenu, NMessageProvider } from 'naive-ui'
import { useStats } from './stores/stats'

const stats = useStats()
const router = useRouter()

onMounted(() => stats.load())
const fmt = (n) => n?.toLocaleString('es-ES') || '0'

const menu = [
  { label: '📥 Cola de Alertas', key: '/' },
  { label: '🔁 Patrones en Bloque', key: '/patrones' },
  { label: '⛓️ Incidentes & Kill Chain', key: '/incidentes' },
  { label: '📋 Registro de Auditoría', key: '/auditoria' },
]

// Marta Puig o Lucía Castro (caso de prompt injection / demo)
function triggerDemoMode() {
  router.push('/alerta/ALR-20261020-011911')
}

// Verde corporativo del reto (Deloitte)
const theme = {
  common: {
    primaryColor: '#0F6E56',
    primaryColorHover: '#1D9E75',
    primaryColorPressed: '#085041',
  },
}
</script>

<style>
body {
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  background: #f7f7f5;
  color: #1e293b;
}
.header {
  display: flex;
  align-items: center;
  padding: 0 24px;
  height: 60px;
  background: #ffffff;
}
.brand {
  font-weight: 700;
  white-space: nowrap;
  display: flex;
  align-items: center;
}
.brand .sub {
  font-weight: 400;
  color: #64748b;
  margin-left: 8px;
  font-size: 13px;
}
.funnel {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: #475569;
  white-space: nowrap;
}
.funnel-pill {
  background: #f1f5f9;
  padding: 4px 8px;
  border-radius: 6px;
}
.funnel-pill-success {
  background: #ecfdf5;
  color: #065f46;
  padding: 4px 8px;
  border-radius: 6px;
  border: 1px solid #a7f3d0;
}
.funnel .arrow {
  color: #94a3b8;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}
</style>
