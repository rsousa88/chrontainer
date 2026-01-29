<template>
  <section class="space-y-8">
    <div class="flex items-end justify-between">
      <div class="space-y-2">
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Dashboard</p>
        <h2 class="text-2xl font-semibold text-surface-50">Containers Overview</h2>
        <p class="text-sm text-surface-400">Live container inventory and quick actions.</p>
      </div>
      <Button variant="ghost" @click="notify">Refresh</Button>
    </div>

    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card>
        <p class="text-xs uppercase tracking-widest text-surface-500">Active</p>
        <p class="mt-3 text-3xl font-semibold text-brand-200">12</p>
        <p class="text-xs text-surface-500">Running containers</p>
      </Card>
      <Card>
        <p class="text-xs uppercase tracking-widest text-surface-500">Paused</p>
        <p class="mt-3 text-3xl font-semibold text-surface-100">0</p>
        <p class="text-xs text-surface-500">Temporarily halted</p>
      </Card>
      <Card>
        <p class="text-xs uppercase tracking-widest text-surface-500">Stopped</p>
        <p class="mt-3 text-3xl font-semibold text-surface-100">3</p>
        <p class="text-xs text-surface-500">Needs attention</p>
      </Card>
      <Card>
        <p class="text-xs uppercase tracking-widest text-surface-500">Updates</p>
        <p class="mt-3 text-3xl font-semibold text-brand-300">2</p>
        <p class="text-xs text-surface-500">Available updates</p>
      </Card>
    </div>

    <ContainersView />
  </section>
</template>

<script setup>
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import ContainersView from './ContainersView.vue'
import { useToastStore } from '../stores/useToastStore'

const toastStore = useToastStore()

const notify = () => {
  toastStore.push({ title: 'Refresh queued', message: 'Fetching latest container data.' })
}
</script>
