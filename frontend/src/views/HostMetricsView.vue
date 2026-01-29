<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Host Metrics</p>
        <h2 class="text-2xl font-semibold text-surface-50">Infrastructure Health</h2>
        <p class="text-sm text-surface-400">Live CPU and memory telemetry per host.</p>
      </div>
      <Button variant="ghost" @click="refresh">Refresh</Button>
    </div>

    <div v-if="store.loading" class="flex justify-end">
      <Spinner label="Fetching metrics" />
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <Card v-for="host in store.metrics" :key="host.host_id" :title="host.name" :subtitle="host.os" eyebrow="Host">
        <div class="grid gap-4 sm:grid-cols-2 text-sm text-surface-300">
          <div>
            <p class="text-xs uppercase text-surface-500">CPU</p>
            <p class="text-sm text-surface-100">{{ host.cpus }} cores</p>
          </div>
          <div>
            <p class="text-xs uppercase text-surface-500">Memory</p>
            <p class="text-sm text-surface-100">{{ host.memory_gb }} GB</p>
          </div>
          <div>
            <p class="text-xs uppercase text-surface-500">Containers</p>
            <p class="text-sm text-surface-100">{{ host.containers_running }} running</p>
          </div>
          <div>
            <p class="text-xs uppercase text-surface-500">Docker</p>
            <p class="text-sm text-surface-100">{{ host.docker_version || 'Unknown' }}</p>
          </div>
        </div>
      </Card>
    </div>
  </section>
</template>

<script setup>
import { onMounted } from 'vue'
import Card from '../components/ui/Card.vue'
import Button from '../components/ui/Button.vue'
import Spinner from '../components/ui/Spinner.vue'
import { useHostStore } from '../stores/useHostStore'

const store = useHostStore()

const refresh = () => store.fetchMetrics()

onMounted(() => {
  store.fetchMetrics()
})
</script>
