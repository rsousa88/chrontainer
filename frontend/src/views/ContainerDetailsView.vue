<template>
  <section class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Container</p>
        <h2 class="text-2xl font-semibold text-surface-50">{{ container?.name || 'Unknown' }}</h2>
        <p class="text-sm text-surface-400">Detailed state and recent activity.</p>
      </div>
      <Button variant="ghost" @click="goBack">Back</Button>
    </div>

    <ContainerDetails :container="container" />

    <Card title="Actions" subtitle="Quick commands for this container">
      <ContainerActions :container="container" />
    </Card>
  </section>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import ContainerDetails from '../components/containers/ContainerDetails.vue'
import ContainerActions from '../components/containers/ContainerActions.vue'
import { useContainerStore } from '../stores/useContainerStore'

const router = useRouter()
const route = useRoute()
const store = useContainerStore()

const containerId = computed(() => route.params.id || route.params.containerId || route.params.container)
const container = computed(() => store.items.find((item) => item.id === containerId.value) || {})

const goBack = () => router.back()

onMounted(() => {
  if (!store.items.length) {
    store.fetchContainers()
  }
})
</script>
