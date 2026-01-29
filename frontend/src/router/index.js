import { createRouter, createWebHistory } from 'vue-router'

const DashboardView = () => import('../views/DashboardView.vue')
const ContainersView = () => import('../views/ContainersView.vue')
const ContainerDetailsView = () => import('../views/ContainerDetailsView.vue')
const ImagesView = () => import('../views/ImagesView.vue')
const LogsView = () => import('../views/LogsView.vue')
const HostMetricsView = () => import('../views/HostMetricsView.vue')
const SettingsView = () => import('../views/SettingsView.vue')

const routes = [
  { path: '/', name: 'dashboard', component: DashboardView },
  { path: '/containers', name: 'containers', component: ContainersView },
  { path: '/containers/:id', name: 'container-details', component: ContainerDetailsView },
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
