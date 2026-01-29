<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Host Metrics</p>
        <h2 class="text-2xl font-semibold text-surface-50">Infrastructure Health</h2>
        <p class="text-sm text-surface-400">Live CPU and memory telemetry per host.</p>
      </div>
      <Button variant="ghost">Refresh</Button>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <Card v-for="host in hosts" :key="host.id" :title="host.name" :subtitle="host.os" eyebrow="Host">
        <div class="grid gap-4 sm:grid-cols-2 text-sm text-surface-300">
          <div>
            <p class="text-xs uppercase text-surface-500">CPU</p>
            <p class="text-sm text-surface-100">{{ host.cpus }} cores</p>
          </div>
          <div>
            <p class="text-xs uppercase text-surface-500">Memory</p>
            <p class="text-sm text-surface-100">{{ host.memory }} GB</p>
          </div>
          <div>
            <p class="text-xs uppercase text-surface-500">Containers</p>
            <p class="text-sm text-surface-100">{{ host.running }} running</p>
          </div>
          <div>
            <p class="text-xs uppercase text-surface-500">Docker</p>
            <p class="text-sm text-surface-100">{{ host.version }}</p>
          </div>
        </div>
      </Card>
    </div>
  </section>
</template>

<script setup>
import Card from '../components/ui/Card.vue'
import Button from '../components/ui/Button.vue'

const hosts = [
  { id: 1, name: 'rpi5', os: 'Debian GNU/Linux', cpus: 4, memory: 7.7, running: 12, version: '27.4.1' },
  { id: 2, name: 'everest', os: 'Synology NAS', cpus: 2, memory: 5.6, running: 14, version: '24.0.2' },
]
</script>
