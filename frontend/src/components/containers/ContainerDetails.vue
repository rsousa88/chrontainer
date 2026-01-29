<template>
  <Card :title="container.name" :subtitle="container.image" eyebrow="Container Details">
    <div class="grid gap-4 text-sm text-surface-200 sm:grid-cols-2">
      <div>
        <p class="text-xs uppercase text-surface-500">Status</p>
        <Badge :tone="statusTone">{{ container.status }}</Badge>
      </div>
      <div>
        <p class="text-xs uppercase text-surface-500">Host</p>
        <p class="text-sm text-surface-100">{{ container.host }}</p>
      </div>
      <div>
        <p class="text-xs uppercase text-surface-500">CPU</p>
        <p class="text-sm text-surface-100">{{ container.cpu }}</p>
      </div>
      <div>
        <p class="text-xs uppercase text-surface-500">Memory</p>
        <p class="text-sm text-surface-100">{{ container.memory }}</p>
      </div>
      <div>
        <p class="text-xs uppercase text-surface-500">IP</p>
        <p class="text-sm text-surface-100">{{ container.ip }}</p>
      </div>
      <div>
        <p class="text-xs uppercase text-surface-500">Tags</p>
        <p class="text-sm text-surface-100">{{ container.tags?.join(', ') || 'None' }}</p>
      </div>
    </div>
  </Card>
</template>

<script setup>
import { computed } from 'vue'
import Card from '../ui/Card.vue'
import Badge from '../ui/Badge.vue'

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
