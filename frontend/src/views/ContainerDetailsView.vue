<template>
  <section class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Container</p>
        <h2 class="text-2xl font-semibold text-surface-50">{{ container.name }}</h2>
        <p class="text-sm text-surface-400">Detailed state and recent activity.</p>
      </div>
      <Button variant="ghost">Back</Button>
    </div>

    <ContainerDetails :container="container" />

    <Card title="Actions" subtitle="Quick commands for this container">
      <ContainerActions />
    </Card>
  </section>
</template>

<script setup>
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import ContainerDetails from '../components/containers/ContainerDetails.vue'
import ContainerActions from '../components/containers/ContainerActions.vue'

const container = {
  id: '1',
  name: 'chrontainer',
  host: 'rpi5',
  status: 'running',
  cpu: '1.3%',
  memory: '220 MB',
  image: 'ghcr.io/rsousa88/chrontainer',
  ip: '192.168.50.21',
  tags: ['core'],
}
</script>
