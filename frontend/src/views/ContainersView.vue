<template>
  <section class="space-y-6">
    <div class="flex flex-col gap-2">
      <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Containers</p>
      <h2 class="text-2xl font-semibold text-surface-50">Fleet Status</h2>
      <p class="text-sm text-surface-400">Monitor all Docker hosts with unified actions.</p>
    </div>

    <div class="flex flex-wrap items-center gap-3 rounded-2xl border border-surface-800 bg-surface-900/60 p-4 text-sm">
      <Input v-model="filters.query" placeholder="Filter by name or image" class="min-w-[220px]" />
      <Select v-model="filters.status" class="min-w-[140px]">
        <option value="">All Statuses</option>
        <option>Running</option>
        <option>Paused</option>
        <option>Stopped</option>
      </Select>
      <Select v-model="filters.host" class="min-w-[140px]">
        <option value="">All Hosts</option>
        <option>rpi5</option>
        <option>everest</option>
      </Select>
      <div class="ml-auto flex items-center gap-2">
        <Button variant="ghost">Clear</Button>
        <Button variant="primary">Refresh</Button>
      </div>
    </div>

    <div class="grid gap-4 lg:hidden">
      <ContainerCard v-for="container in containers" :key="container.id" :container="container" />
    </div>

    <div class="hidden lg:block">
      <ContainerTable :containers="containers" />
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import Button from '../components/ui/Button.vue'
import ContainerCard from '../components/containers/ContainerCard.vue'
import ContainerTable from '../components/containers/ContainerTable.vue'

const filters = ref({
  query: '',
  status: '',
  host: '',
})

const containers = [
  {
    id: '1',
    name: 'chrontainer',
    host: 'rpi5',
    status: 'running',
    cpu: '1.3%',
    memory: '220 MB',
    image: 'ghcr.io/rsousa88/chrontainer',
    ip: '192.168.50.21',
    tags: ['core'],
  },
  {
    id: '2',
    name: 'grafana',
    host: 'everest',
    status: 'running',
    cpu: '0.4%',
    memory: '410 MB',
    image: 'grafana/grafana-enterprise',
    ip: '192.168.50.12',
    tags: ['monitoring'],
  },
  {
    id: '3',
    name: 'rabbitmq',
    host: 'everest',
    status: 'stopped',
    cpu: '0%',
    memory: '0 MB',
    image: 'rabbitmq:management-alpine',
    ip: '192.168.50.4',
    tags: ['queue'],
  },
]
</script>
