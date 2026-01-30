<template>
  <div ref="rootEl" class="flex flex-nowrap items-center gap-1" :class="align === 'right' ? 'justify-end' : ''">
    <Button size="icon" variant="ghost" aria-label="Restart" title="Restart" @click="runAction('restart')">
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 12a9 9 0 1 1 3 6.7" />
        <path d="M3 21v-6h6" />
      </svg>
    </Button>
    <Button
      v-if="canStop"
      size="icon"
      variant="ghost"
      aria-label="Stop"
      title="Stop"
      @click="runAction('stop')"
    >
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
        <rect x="6" y="6" width="12" height="12" rx="2" />
      </svg>
    </Button>
    <Button
      v-if="canStart"
      size="icon"
      variant="ghost"
      aria-label="Start"
      title="Start"
      @click="runAction('start')"
    >
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
        <path d="M8 5v14l11-7z" />
      </svg>
    </Button>
    <Button size="icon" variant="ghost" aria-label="Logs" title="Logs" @click="openLogs">
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M4 6h16" />
        <path d="M4 12h16" />
        <path d="M4 18h16" />
      </svg>
    </Button>
    <Button
      v-show="updateAvailable"
      size="icon"
      variant="ghost"
      aria-label="Update"
      title="Update"
      @click="runAction('update')"
    >
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 3v12" />
        <path d="m7 10 5 5 5-5" />
        <path d="M5 21h14" />
      </svg>
    </Button>
    <Button
      v-show="!updateAvailable"
      size="icon"
      variant="ghost"
      aria-label="Check updates"
      title="Check updates"
      :disabled="updateBusy"
      @click="checkUpdates"
    >
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 12a9 9 0 1 1-3-6.7" />
        <path d="M21 3v6h-6" />
      </svg>
    </Button>
    <div class="relative">
      <Button size="icon" variant="ghost" aria-label="More actions" title="More actions" @click="toggleMenu">
        <svg class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
          <circle cx="5" cy="12" r="2" />
          <circle cx="12" cy="12" r="2" />
          <circle cx="19" cy="12" r="2" />
        </svg>
      </Button>
      <div
        ref="menuEl"
        v-if="menuOpen"
        class="absolute right-0 z-10 mt-2 w-40 rounded-xl border border-surface-800 bg-surface-900 p-2 text-xs text-surface-200 shadow-xl"
      >
        <button
          v-if="isPaused"
          class="flex w-full items-center gap-2 rounded-lg px-2 py-1 hover:bg-surface-800"
          @click="runAction('unpause')"
        >
          Unpause
        </button>
        <button
          v-else
          class="flex w-full items-center gap-2 rounded-lg px-2 py-1 hover:bg-surface-800"
          @click="runAction('pause')"
        >
          Pause
        </button>
        <button class="flex w-full items-center gap-2 rounded-lg px-2 py-1 hover:bg-surface-800" @click="openSchedule">Add Schedule</button>
        <button v-if="webuiUrl" class="flex w-full items-center gap-2 rounded-lg px-2 py-1 hover:bg-surface-800" @click="openWebui">Open UI</button>
      </div>
    </div>
  </div>

  <Modal
    :open="logsOpen"
    title="Container Logs"
    :subtitle="container?.name"
    panel-class="w-[90vw] max-w-[90vw] h-[75vh]"
    body-class="h-full text-left"
    @close="closeLogs"
  >
    <div class="flex items-center justify-between gap-2 text-xs text-surface-400">
      <label class="flex items-center gap-2">
        <input type="checkbox" v-model="autoRefresh" class="h-4 w-4 rounded border-surface-600 bg-surface-800" />
        Auto-refresh
      </label>
      <span v-if="logsLoading">Loading...</span>
    </div>
    <div
      ref="logsContainer"
      class="mt-3 h-[58vh] overflow-auto rounded-xl border border-surface-800 bg-surface-950 p-3 text-xs text-surface-200"
    >
      <pre class="whitespace-pre-wrap">{{ logsContent || (logsLoading ? 'Loading logs...' : 'No logs available.') }}</pre>
    </div>
    <template #actions>
      <Button variant="ghost" @click="closeLogs">Close</Button>
    </template>
  </Modal>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import Button from '../ui/Button.vue'
import Modal from '../ui/Modal.vue'
import { useToastStore } from '../../stores/useToastStore'
import api from '../../lib/api'

const props = defineProps({
  container: {
    type: Object,
    required: true,
  },
  align: {
    type: String,
    default: 'left',
  },
})

const toastStore = useToastStore()
const router = useRouter()

const containerPayload = computed(() => ({
  name: props.container?.name || 'unknown',
  host_id: props.container?.host_id || props.container?.hostId || 1,
}))
const statusValue = computed(() => (props.container?.status || '').toLowerCase())
const isPaused = computed(() => statusValue.value.includes('paused'))
const isRunning = computed(() => statusValue.value.includes('running'))
const canStop = computed(() => isRunning.value || isPaused.value)
const canStart = computed(() => !isRunning.value && !isPaused.value)
const updateAvailable = computed(() => {
  const status = props.container?.update_status || props.container?.updateStatus
  const raw = status?.has_update
  return raw === true || raw === 1 || raw === '1' || raw === 'true'
})

const logsOpen = ref(false)
const logsContent = ref('')
const logsLoading = ref(false)
const updateBusy = ref(false)
const webuiUrl = computed(() => props.container?.webui_url || props.container?.webuiUrl || props.container?.webui_url_label)
const logsContainer = ref(null)
const autoRefresh = ref(true)
const refreshTimer = ref(null)
const menuOpen = ref(false)
const rootEl = ref(null)
const menuEl = ref(null)

const runAction = async (action) => {
  const id = props.container?.id
  if (!id) {
    toastStore.push({ title: 'Action failed', message: 'Missing container ID.', tone: 'danger' })
    return
  }
  menuOpen.value = false

  try {
    const { data } = await api.post(`/container/${id}/${action}`, containerPayload.value)
    if (data?.success === false) {
      toastStore.push({ title: 'Action failed', message: data?.message || 'Request failed.', tone: 'danger' })
      return
    }
    if (action === 'update' && props.container) {
      props.container.update_status = { ...(props.container.update_status || {}), has_update: false }
    }
    toastStore.push({ title: 'Action queued', message: data?.message || `${action} request sent.` })
  } catch (err) {
    toastStore.push({ title: 'Action failed', message: err?.response?.data?.error || 'Request failed.', tone: 'danger' })
  }
}

const checkUpdates = async () => {
  const id = props.container?.id
  const hostId = containerPayload.value.host_id
  if (!id) {
    toastStore.push({ title: 'Update check failed', message: 'Missing container ID.', tone: 'danger' })
    return
  }
  if (updateBusy.value) return
  menuOpen.value = false
  updateBusy.value = true
  try {
    const { data } = await api.get(`/container/${id}/check-update`, { params: { host_id: hostId } })
    if (data?.has_update) {
      if (props.container) {
        props.container.update_status = { ...(props.container.update_status || {}), has_update: true }
      }
      toastStore.push({ title: 'Update available', message: 'A newer image is available.' })
    } else if (data?.error) {
      toastStore.push({ title: 'Update check failed', message: data.error, tone: 'danger' })
    } else {
      if (props.container) {
        props.container.update_status = { ...(props.container.update_status || {}), has_update: false }
      }
      toastStore.push({ title: 'Up to date', message: 'No updates found.' })
    }
  } catch (err) {
    const status = err?.response?.status
    if (status === 429) {
      toastStore.push({
        title: 'Update check limited',
        message: 'Registry rate limit hit. Authenticate with the registry to raise limits.',
        tone: 'warning',
      })
    } else {
      toastStore.push({
        title: 'Update check failed',
        message: err?.response?.data?.error || 'Unable to check updates.',
        tone: 'danger',
      })
    }
  } finally {
    setTimeout(() => {
      updateBusy.value = false
    }, 3000)
  }
}

const fetchLogs = async () => {
  const id = props.container?.id
  const hostId = containerPayload.value.host_id
  if (!id) {
    toastStore.push({ title: 'Logs unavailable', message: 'Missing container ID.', tone: 'danger' })
    return
  }
  logsLoading.value = true
  try {
    const { data } = await api.get(`/container/${id}/logs`, { params: { host_id: hostId, tail: 200 } })
    logsContent.value = data?.logs || ''
  } catch (err) {
    logsContent.value = err?.response?.data?.error || 'Unable to load logs.'
  } finally {
    logsLoading.value = false
  }
}

const openLogs = async () => {
  menuOpen.value = false
  logsOpen.value = true
  await fetchLogs()
}

const closeLogs = () => {
  logsOpen.value = false
}

const openWebui = () => {
  if (!webuiUrl.value) return
  menuOpen.value = false
  window.open(webuiUrl.value, '_blank', 'noopener')
}

const openSchedule = () => {
  menuOpen.value = false
  router.push({
    name: 'schedules',
    query: {
      host_id: containerPayload.value.host_id,
      container_id: props.container?.id,
      container_name: props.container?.name,
    },
  })
}

const toggleMenu = () => {
  menuOpen.value = !menuOpen.value
}

const handleOutsideClick = (event) => {
  if (!menuOpen.value) return
  if (rootEl.value && !rootEl.value.contains(event.target)) {
    menuOpen.value = false
  }
}

const scrollLogsToBottom = async () => {
  await nextTick()
  if (!logsContainer.value) return
  logsContainer.value.scrollTop = logsContainer.value.scrollHeight
}

watch(logsContent, () => {
  scrollLogsToBottom()
})

watch([logsOpen, autoRefresh], ([open, enabled]) => {
  if (!open || !enabled) {
    if (refreshTimer.value) {
      clearInterval(refreshTimer.value)
      refreshTimer.value = null
    }
    return
  }
  if (!refreshTimer.value) {
    refreshTimer.value = setInterval(() => {
      fetchLogs()
    }, 2000)
  }
})

onBeforeUnmount(() => {
  if (refreshTimer.value) {
    clearInterval(refreshTimer.value)
  }
  document.removeEventListener('click', handleOutsideClick)
})

onMounted(() => {
  document.addEventListener('click', handleOutsideClick)
})


</script>
