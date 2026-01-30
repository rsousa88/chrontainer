<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Logs</p>
        <h2 class="text-2xl font-semibold text-surface-50">Activity Stream</h2>
        <p class="text-sm text-surface-400">Inspect container events and application logs.</p>
      </div>
      <Button variant="ghost" @click="refresh">Refresh</Button>
    </div>

    <div v-if="logStore.loading" class="flex justify-end">
      <Spinner label="Loading logs" />
    </div>

    <Card>
      <div class="space-y-3 text-sm text-surface-300">
        <div v-for="entry in logStore.entries" :key="entry.id" class="rounded-xl border border-surface-800 bg-surface-900/60 px-4 py-3">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div class="space-y-1">
              <div class="text-sm font-semibold text-surface-100">
                {{ entry.container_name || 'System' }}
              </div>
              <div class="flex flex-wrap items-center gap-2 text-xs text-surface-400">
                <span v-if="entry.action">{{ entry.action }}</span>
                <Badge v-if="entry.status" :tone="statusTone(entry.status)">{{ entry.status }}</Badge>
                <span v-if="entry.host_name">Host: {{ entry.host_name }}</span>
              </div>
            </div>
            <span class="text-xs text-surface-500">{{ entry.timestamp || entry.created_at || '' }}</span>
          </div>
          <p class="mt-2 text-sm text-surface-300">{{ entry.message || entry.details || '' }}</p>
        </div>
      </div>
    </Card>
  </section>
</template>

<script setup>
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import Badge from '../components/ui/Badge.vue'
import { useToastStore } from '../stores/useToastStore'
import Spinner from '../components/ui/Spinner.vue'
import { useLogStore } from '../stores/useLogStore'
import { onMounted } from 'vue'

const toastStore = useToastStore()
const logStore = useLogStore()

const statusTone = (status) => {
  const value = status?.toLowerCase() || ''
  if (value.includes('success')) return 'success'
  if (value.includes('error') || value.includes('fail')) return 'danger'
  if (value.includes('warn')) return 'warning'
  return 'neutral'
}

const refresh = async () => {
  await logStore.fetchLogs()
  toastStore.push({ title: 'Logs refreshed', message: 'Latest log entries loaded.' })
}

onMounted(() => {
  logStore.fetchLogs()
})
</script>
