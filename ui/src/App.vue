<template>
  <n-config-provider :theme-overrides="theme">
    <n-message-provider>
      <n-layout style="min-height: 100vh">
        <n-layout-header bordered class="header">
          <!-- Logo y marca -->
          <div class="brand" @click="$router.push('/')" style="cursor: pointer;">
            <span class="brand-title">🛡️ SOC N1 · Tarvia</span>
            <span class="sub">Triaje con IA</span>
          </div>

          <!-- Navegación optimizada en anchura -->
          <nav class="nav-links">
            <button
              v-for="item in menu"
              :key="item.key"
              class="nav-btn"
              :class="{ active: isNavActive(item.key) }"
              @click="$router.push(item.key)"
            >
              <span class="nav-icon">{{ item.icon }}</span>
              <span class="nav-label">{{ item.label }}</span>
            </button>
          </nav>

          <!-- Embudo de reducción y tiempo ahorrado siempre visible -->
          <div v-if="stats.data" class="funnel">
            <span class="funnel-pill"><b>{{ fmt(stats.data.alerts) }}</b> alertas</span>
            <span class="arrow">→</span>
            <span class="funnel-pill"><b>{{ stats.data.patterns }}</b> patrones</span>
            <span class="arrow">→</span>
            <span class="funnel-pill outlier-pill"><b>{{ stats.data.outliers }}</b> atípicos</span>
            <span class="arrow">→</span>
            <span class="funnel-pill-success">
              ⏱️ <b>{{ savedTimeText }}</b> ahorradas
            </span>
          </div>

          <!-- Botón de Modo Demo -->
          <n-button
            type="primary"
            secondary
            size="small"
            class="demo-btn"
            @click="triggerDemoMode"
          >
            ▶️ Demo
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
import { computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NButton, NConfigProvider, NLayout, NLayoutContent, NLayoutHeader, NMessageProvider } from 'naive-ui'
import { useStats } from './stores/stats'

const stats = useStats()
const router = useRouter()
const route = useRoute()

onMounted(() => stats.load())
const fmt = (n) => n?.toLocaleString('es-ES') || '0'

// Nombres concisos para evitar desbordamiento horizontal en cualquier resolución
const menu = [
  { label: 'Cola', key: '/', icon: '📥' },
  { label: 'Patrones', key: '/patrones', icon: '🔁' },
  { label: 'Incidentes', key: '/incidentes', icon: '⛓️' },
  { label: 'Auditoría', key: '/auditoria', icon: '📋' },
]

function isNavActive(key) {
  if (key === '/') return route.path === '/' || route.path.startsWith('/alerta/')
  return route.path.startsWith(key)
}

const savedTimeText = computed(() => {
  if (!stats.data) return '0h'
  const mins = stats.data.minutes_saved || (stats.data.triaged * 15) || 60
  if (mins >= 60) {
    return `${Math.round(mins / 60)}h`
  }
  return `${mins}m`
})

function triggerDemoMode() {
  router.push('/alerta/ALR-20261020-011911')
}

// Paleta verde corporativo del reto (Deloitte)
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
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #f7f7f5;
  color: #1e293b;
}
.header {
  display: flex;
  align-items: center;
  padding: 0 16px;
  height: 58px;
  background: #ffffff;
  border-bottom: 1px solid #e2e8f0;
  overflow-x: auto;
  white-space: nowrap;
}
.brand {
  font-weight: 700;
  white-space: nowrap;
  display: flex;
  align-items: center;
  flex-shrink: 0;
}
.brand-title {
  color: #0F6E56;
  font-size: 16px;
  font-weight: 800;
}
.brand .sub {
  font-weight: 500;
  color: #64748b;
  margin-left: 6px;
  font-size: 11px;
  background: #f1f5f9;
  padding: 2px 5px;
  border-radius: 4px;
}

/* Barra de navegación superior */
.nav-links {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-left: 14px;
  flex-shrink: 0;
}
.nav-btn {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 6px;
  padding: 5px 9px;
  font-size: 12.5px;
  font-weight: 500;
  cursor: pointer;
  color: #475569;
  display: flex;
  align-items: center;
  gap: 5px;
  transition: all 0.15s ease-in-out;
  white-space: nowrap;
}
.nav-btn:hover {
  background: #f8fafc;
  color: #0F6E56;
  border-color: #e2e8f0;
}
.nav-btn.active {
  background: #eef8f5;
  color: #0F6E56;
  font-weight: 600;
  border-color: #a7f3d0;
}
.nav-icon {
  font-size: 13px;
}

/* Embudo de reducción */
.funnel {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11.5px;
  color: #475569;
  white-space: nowrap;
  flex-shrink: 0;
  padding: 0 8px;
}
.funnel-pill {
  background: #f1f5f9;
  padding: 3px 6px;
  border-radius: 5px;
}
.outlier-pill {
  background: #fef3c7;
  color: #92400e;
  border: 1px solid #fde68a;
}
.funnel-pill-success {
  background: #ecfdf5;
  color: #065f46;
  padding: 3px 7px;
  border-radius: 5px;
  border: 1px solid #a7f3d0;
  font-weight: 600;
}
.funnel .arrow {
  color: #94a3b8;
  font-size: 10px;
}
.demo-btn {
  margin-left: 8px;
  font-weight: 700;
  flex-shrink: 0;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}
</style>
