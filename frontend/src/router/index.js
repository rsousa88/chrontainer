import { createRouter, createWebHistory } from 'vue-router'

const DashboardView = () => import('../views/DashboardView.vue')
const ImagesView = () => import('../views/ImagesView.vue')
const LogsView = () => import('../views/LogsView.vue')
const HostMetricsView = () => import('../views/HostMetricsView.vue')
const SettingsView = () => import('../views/SettingsView.vue')

const routes = [
  { path: '/', name: 'dashboard', component: DashboardView },
  { path: '/images', name: 'images', component: ImagesView },
  { path: '/logs', name: 'logs', component: LogsView },
  { path: '/metrics', name: 'metrics', component: HostMetricsView },
  { path: '/settings', name: 'settings', component: SettingsView },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
