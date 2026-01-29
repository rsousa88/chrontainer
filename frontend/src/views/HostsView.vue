<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Hosts</p>
        <h2 class="text-2xl font-semibold text-surface-50">Docker Hosts</h2>
        <p class="text-sm text-surface-400">Manage host connections and colors.</p>
      </div>
      <Button variant="primary">Add Host</Button>
    </div>

    <Table>
      <template #head>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Name</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">URL</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Status</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
      </template>
      <tr v-for="host in hosts" :key="host.id">
        <td class="px-4 py-4 text-sm text-surface-100">{{ host.name }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ host.url }}</td>
        <td class="px-4 py-4">
          <Badge :tone="host.enabled ? 'success' : 'danger'">
            {{ host.enabled ? 'Enabled' : 'Disabled' }}
          </Badge>
        </td>
        <td class="px-4 py-4">
          <Button variant="ghost">Edit</Button>
        </td>
      </tr>
    </Table>
  </section>
</template>

<script setup>
import Table from '../components/ui/Table.vue'
import Button from '../components/ui/Button.vue'
import Badge from '../components/ui/Badge.vue'

const hosts = [
  { id: 1, name: 'rpi5', url: 'unix:///var/run/docker.sock', enabled: true },
  { id: 2, name: 'everest', url: 'tcp://192.168.50.22:2375', enabled: true },
]
</script>
