<template>
  <Card>
    <div class="flex items-center justify-between">
      <div>
        <span
          class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold"
          :style="{
            backgroundColor: container.host_color || '#2c3542',
            color: container.host_text_color || '#f8fafc'
          }"
        >
          {{ container.host || container.host_name || '—' }}
        </span>
        <h3 class="mt-2 text-lg font-semibold text-surface-50">{{ container.name }}</h3>
      </div>
      <Badge :tone="statusTone">{{ container.status }}</Badge>
    </div>
    <div class="mt-4 grid grid-cols-2 gap-4 text-xs text-surface-400">
      <div>
        <p>CPU</p>
        <p class="text-sm text-surface-100">{{ container.cpu }}</p>
      </div>
      <div>
        <p>Memory</p>
        <p class="text-sm text-surface-100">{{ container.memory }}</p>
      </div>
      <div>
        <p>Image</p>
        <p class="text-sm text-surface-100">{{ container.image }}</p>
      </div>
      <div>
        <p>IP</p>
        <p class="text-sm text-surface-100">{{ container.ip }}</p>
      </div>
    </div>
    <div class="mt-4">
      <ContainerActions :container="container" />
    </div>
  </Card>
</template>

<script setup>
import { computed } from 'vue'
import Card from '../ui/Card.vue'
import Badge from '../ui/Badge.vue'
import ContainerActions from './ContainerActions.vue'

const props = defineProps({
  container: {
    type: Object,
    required: true,
  },
})

const statusTone = computed(() => {
  const status = props.container.status?.toLowerCase() || 'unknown'
  if (status.includes('running')) return 'success'
  if (status.includes('paused')) return 'warning'
  if (status.includes('stopped') || status.includes('exited')) return 'danger'
  return 'neutral'
})
</script>
