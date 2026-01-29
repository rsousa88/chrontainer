<template>
  <div class="flex flex-wrap items-center gap-2">
    <Button variant="ghost" aria-label="Restart" title="Restart" @click="runAction('restart')">
      <IconRefresh />
    </Button>
    <Button variant="ghost" aria-label="Stop" title="Stop" @click="runAction('stop')">
      <IconStop />
    </Button>
    <Button variant="ghost" aria-label="Start" title="Start" @click="runAction('start')">
      <IconPlay />
    </Button>
    <Button variant="ghost" aria-label="Pause" title="Pause" @click="runAction('pause')">
      <IconPause />
    </Button>
    <Button variant="ghost" aria-label="Unpause" title="Unpause" @click="runAction('unpause')">
      <IconPlay />
    </Button>
    <Button variant="ghost" aria-label="Update" title="Update" @click="runAction('update')">
      <IconUpload />
    </Button>
    <Button variant="ghost" aria-label="Check Updates" title="Check Updates" :disabled="updateBusy" @click="checkUpdates">
      <IconCheck />
    </Button>
    <Button variant="ghost" aria-label="Logs" title="Logs" @click="openLogs">
      <IconList />
    </Button>
    <Button v-if="webuiUrl" variant="ghost" aria-label="Open UI" title="Open UI" @click="openWebui">
      <IconExternal />
    </Button>
  </div>

  <Modal
    :open="logsOpen"
    title="Container Logs"
    :subtitle="container?.name"
    panel-class="w-[90vw] max-w-none h-[75vh]"
    body-class="h-full"
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
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import Button from '../ui/Button.vue'
import Modal from '../ui/Modal.vue'
import { useToastStore } from '../../stores/useToastStore'
import api from '../../lib/api'

const props = defineProps({
  container: {
    type: Object,
    required: true,
  },
})

const toastStore = useToastStore()

const containerPayload = computed(() => ({
  name: props.container?.name || 'unknown',
  host_id: props.container?.host_id || props.container?.hostId || 1,
}))

const logsOpen = ref(false)
const logsContent = ref('')
const logsLoading = ref(false)
const updateBusy = ref(false)
const webuiUrl = computed(() => props.container?.webui_url || props.container?.webuiUrl || props.container?.webui_url_label)
const logsContainer = ref(null)
const autoRefresh = ref(true)
const refreshTimer = ref(null)

const runAction = async (action) => {
  const id = props.container?.id
  if (!id) {
    toastStore.push({ title: 'Action failed', message: 'Missing container ID.', tone: 'danger' })
    return
  }

  try {
    const { data } = await api.post(`/container/${id}/${action}`, containerPayload.value)
    if (data?.success === false) {
      toastStore.push({ title: 'Action failed', message: data?.message || 'Request failed.', tone: 'danger' })
      return
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
  updateBusy.value = true
  try {
    const { data } = await api.get(`/container/${id}/check-update`, { params: { host_id: hostId } })
    if (data?.has_update) {
      toastStore.push({ title: 'Update available', message: 'A newer image is available.' })
    } else if (data?.error) {
      toastStore.push({ title: 'Update check failed', message: data.error, tone: 'danger' })
    } else {
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
  logsOpen.value = true
  await fetchLogs()
}

const closeLogs = () => {
  logsOpen.value = false
}

const openWebui = () => {
  if (!webuiUrl.value) return
  window.open(webuiUrl.value, '_blank', 'noopener')
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
})

const IconRefresh = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M21 12a9 9 0 1 1-3-6.7\"/><path d=\"M21 3v6h-6\"/></svg>',
}
const IconStop = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><rect x=\"6\" y=\"6\" width=\"12\" height=\"12\" rx=\"2\"/></svg>',
}
const IconPlay = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M8 5v14l11-7z\"/></svg>',
}
const IconPause = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><rect x=\"6\" y=\"5\" width=\"4\" height=\"14\" rx=\"1\"/><rect x=\"14\" y=\"5\" width=\"4\" height=\"14\" rx=\"1\"/></svg>',
}
const IconUpload = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M12 16V4\"/><path d=\"m5 11 7-7 7 7\"/><path d=\"M4 20h16\"/></svg>',
}
const IconCheck = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"m5 12 4 4 10-10\"/></svg>',
}
const IconList = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M8 6h13\"/><path d=\"M8 12h13\"/><path d=\"M8 18h13\"/><circle cx=\"4\" cy=\"6\" r=\"1\"/><circle cx=\"4\" cy=\"12\" r=\"1\"/><circle cx=\"4\" cy=\"18\" r=\"1\"/></svg>',
}
const IconExternal = {
  template:
    '<svg class=\"h-4 w-4\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M14 3h7v7\"/><path d=\"M10 14 21 3\"/><path d=\"M21 14v7H3V3h7\"/></svg>',
}
</script>
