<template>
  <div class="flex flex-wrap items-center gap-2">
    <Button variant="ghost" @click="runAction('restart')">Restart</Button>
    <Button variant="ghost" @click="runAction('stop')">Stop</Button>
    <Button variant="ghost" @click="runAction('start')">Start</Button>
    <Button variant="ghost" @click="runAction('update')">Update</Button>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import Button from '../ui/Button.vue'
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
</script>
