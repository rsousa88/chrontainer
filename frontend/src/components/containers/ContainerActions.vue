<template>
  <div class="flex flex-wrap items-center gap-2">
    <Button variant="ghost" @click="runAction('restart')">Restart</Button>
    <Button variant="ghost" @click="runAction('stop')">Stop</Button>
    <Button variant="ghost" @click="runAction('start')">Start</Button>
    <Button variant="ghost" @click="runAction('update')">Update</Button>
    <Button variant="ghost" @click="checkUpdates">Check Updates</Button>
    <Button variant="ghost" @click="openLogs">Logs</Button>
  </div>

  <Modal :open="logsOpen" title="Container Logs" :subtitle="container?.name" @close="closeLogs">
    <div class="max-h-96 overflow-auto rounded-xl border border-surface-800 bg-surface-950 p-3 text-xs text-surface-200">
      <pre class="whitespace-pre-wrap">{{ logsContent || (logsLoading ? 'Loading logs...' : 'No logs available.') }}</pre>
    </div>
    <template #actions>
      <Button variant="ghost" @click="closeLogs">Close</Button>
    </template>
  </Modal>
</template>

<script setup>
import { computed, ref } from 'vue'
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
    toastStore.push({
      title: 'Update check failed',
      message: err?.response?.data?.error || 'Unable to check updates.',
      tone: 'danger',
    })
  }
}

const openLogs = async () => {
  const id = props.container?.id
  const hostId = containerPayload.value.host_id
  if (!id) {
    toastStore.push({ title: 'Logs unavailable', message: 'Missing container ID.', tone: 'danger' })
    return
  }
  logsOpen.value = true
  logsLoading.value = true
  logsContent.value = ''
  try {
    const { data } = await api.get(`/container/${id}/logs`, { params: { host_id: hostId, tail: 200 } })
    logsContent.value = data?.logs || ''
  } catch (err) {
    logsContent.value = err?.response?.data?.error || 'Unable to load logs.'
  } finally {
    logsLoading.value = false
  }
}

const closeLogs = () => {
  logsOpen.value = false
}
</script>
