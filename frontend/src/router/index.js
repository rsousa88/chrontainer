import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/useAuthStore'

const DashboardView = () => import('../views/DashboardView.vue')
const ContainersView = () => import('../views/ContainersView.vue')
const ContainerDetailsView = () => import('../views/ContainerDetailsView.vue')
const ImagesView = () => import('../views/ImagesView.vue')
const LogsView = () => import('../views/LogsView.vue')
const HostMetricsView = () => import('../views/HostMetricsView.vue')
const SettingsView = () => import('../views/SettingsView.vue')
const SchedulesView = () => import('../views/SchedulesView.vue')
const HostsView = () => import('../views/HostsView.vue')
const LoginView = () => import('../views/LoginView.vue')

const routes = [
  { path: '/', name: 'dashboard', component: DashboardView, meta: { requiresAuth: true } },
  { path: '/containers', name: 'containers', component: ContainersView, meta: { requiresAuth: true } },
  { path: '/containers/:id', name: 'container-details', component: ContainerDetailsView, meta: { requiresAuth: true } },
  { path: '/images', name: 'images', component: ImagesView, meta: { requiresAuth: true } },
  { path: '/logs', name: 'logs', component: LogsView, meta: { requiresAuth: true } },
  { path: '/metrics', name: 'metrics', component: HostMetricsView, meta: { requiresAuth: true } },
  { path: '/settings', name: 'settings', component: SettingsView, meta: { requiresAuth: true } },
  { path: '/schedules', name: 'schedules', component: SchedulesView, meta: { requiresAuth: true } },
  { path: '/hosts', name: 'hosts', component: HostsView, meta: { requiresAuth: true } },
  { path: '/login', name: 'login', component: LoginView },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (!auth.user && to.meta?.requiresAuth) {
    await auth.fetchUser()
  }
  if (to.meta?.requiresAuth && !auth.user) {
    return { name: 'login' }
  }
  if (to.name === 'login' && auth.user) {
    return { name: 'dashboard' }
  }
  return true
})

export default router
