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
        <Button variant="ghost" @click="refresh">Clear</Button>
        <Button variant="primary" @click="refresh">Refresh</Button>
      </div>
    </div>

    <div v-if="store.loading" class="flex justify-end">
      <Spinner label="Fetching containers" />
    </div>

    <div class="grid gap-4 lg:hidden">
      <ContainerCard v-for="container in store.items" :key="container.id" :container="container" />
    </div>

    <div class="hidden lg:block">
      <ContainerTable :containers="store.items" />
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import Button from '../components/ui/Button.vue'
import Spinner from '../components/ui/Spinner.vue'
import ContainerCard from '../components/containers/ContainerCard.vue'
import ContainerTable from '../components/containers/ContainerTable.vue'
import { useContainerStore } from '../stores/useContainerStore'

const filters = ref({
  query: '',
  status: '',
  host: '',
})

const store = useContainerStore()

const refresh = () => store.fetchContainers()

onMounted(() => {
  store.fetchContainers()
})
</script>
