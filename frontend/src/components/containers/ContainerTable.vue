<template>
  <Table>
    <template #head>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Name</th>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Host</th>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Status</th>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">CPU</th>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Memory</th>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Image</th>
      <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
    </template>
    <tr v-for="container in containers" :key="container.id">
      <td class="px-4 py-4 text-sm font-semibold text-surface-50">{{ container.name }}</td>
      <td class="px-4 py-4 text-sm text-surface-300">{{ container.host || container.host_name || '—' }}</td>
      <td class="px-4 py-4">
        <Badge :tone="statusTone(container.status)">{{ container.status }}</Badge>
      </td>
      <td class="px-4 py-4 text-sm text-surface-200">{{ container.cpu }}</td>
      <td class="px-4 py-4 text-sm text-surface-200">{{ container.memory }}</td>
      <td class="px-4 py-4 text-sm text-surface-200">{{ container.image }}</td>
      <td class="px-4 py-4">
        <ContainerActions :container="container" />
      </td>
    </tr>
  </Table>
</template>

<script setup>
import Table from '../ui/Table.vue'
import Badge from '../ui/Badge.vue'
import ContainerActions from './ContainerActions.vue'

const props = defineProps({
  containers: {
    type: Array,
    default: () => [],
  },
})

const statusTone = (status) => {
  const value = status?.toLowerCase() || ''
  if (value.includes('running')) return 'success'
  if (value.includes('paused')) return 'warning'
  if (value.includes('stopped') || value.includes('exited')) return 'danger'
  return 'neutral'
}
</script>
