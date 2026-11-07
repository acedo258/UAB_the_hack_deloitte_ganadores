import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import QueueView from './views/QueueView.vue'
import TicketView from './views/TicketView.vue'
import PatternsView from './views/PatternsView.vue'
import IncidentsView from './views/IncidentsView.vue'
import AuditView from './views/AuditView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: QueueView },
    { path: '/alerta/:id', component: TicketView, props: true },
    { path: '/patrones', component: PatternsView },
    { path: '/incidentes', component: IncidentsView },
    { path: '/auditoria', component: AuditView },
  ],
})

createApp(App).use(createPinia()).use(router).mount('#app')
