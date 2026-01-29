<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Logs</p>
        <h2 class="text-2xl font-semibold text-surface-50">Activity Stream</h2>
        <p class="text-sm text-surface-400">Inspect container events and application logs.</p>
      </div>
      <Button variant="ghost" @click="notify">Refresh</Button>
    </div>

    <Card>
      <div class="space-y-3 text-sm text-surface-300">
        <div v-for="entry in logs" :key="entry.id" class="rounded-xl border border-surface-800 bg-surface-900/60 px-4 py-3">
          <div class="flex items-center justify-between">
            <span class="font-semibold text-surface-100">{{ entry.source }}</span>
            <span class="text-xs text-surface-500">{{ entry.timestamp }}</span>
          </div>
          <p class="mt-2 text-sm text-surface-300">{{ entry.message }}</p>
        </div>
      </div>
    </Card>
  </section>
</template>

<script setup>
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import { useToastStore } from '../stores/useToastStore'

const toastStore = useToastStore()

const logs = [
  { id: 1, source: 'chrontainer', message: 'Scheduler started', timestamp: 'Just now' },
  { id: 2, source: 'socket-proxy', message: 'Connected to docker host', timestamp: '2m ago' },
]

const notify = () => {
  toastStore.push({ title: 'Logs refreshed', message: 'Latest log entries loaded.' })
}
</script>
