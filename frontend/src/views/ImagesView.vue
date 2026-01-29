<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Images</p>
        <h2 class="text-2xl font-semibold text-surface-50">Image Library</h2>
        <p class="text-sm text-surface-400">Review and prune unused images.</p>
      </div>
      <div class="flex items-center gap-2">
        <Button variant="ghost">Refresh</Button>
        <Button variant="danger">Prune Unused</Button>
      </div>
    </div>

    <Card>
      <div class="grid gap-4 md:grid-cols-3">
        <Input v-model="filters.query" label="Search" placeholder="Filter images" />
        <Select v-model="filters.host" label="Host">
          <option value="">All Hosts</option>
          <option>rpi5</option>
          <option>everest</option>
        </Select>
        <Select v-model="filters.unused" label="Unused">
          <option value="">All</option>
          <option value="true">Unused only</option>
        </Select>
      </div>
    </Card>

    <Table>
      <template #head>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Repository</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Tag</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Image ID</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Size</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Containers</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
      </template>
      <tr v-for="image in images" :key="image.id">
        <td class="px-4 py-4 text-sm text-surface-100">{{ image.repo }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ image.tag }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ image.shortId }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ image.size }}</td>
        <td class="px-4 py-4">
          <Badge :tone="image.containers === 0 ? 'warning' : 'info'">{{ image.containers }}</Badge>
        </td>
        <td class="px-4 py-4">
          <Button variant="ghost">Delete</Button>
        </td>
      </tr>
    </Table>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import Card from '../components/ui/Card.vue'
import Table from '../components/ui/Table.vue'
import Badge from '../components/ui/Badge.vue'
import Button from '../components/ui/Button.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'

const filters = ref({
  query: '',
  host: '',
  unused: '',
})

const images = [
  { id: 1, repo: 'ghcr.io/rsousa88/chrontainer', tag: 'latest', shortId: 'a1b2c3d4', size: '389 MB', containers: 1 },
  { id: 2, repo: 'grafana/grafana-enterprise', tag: 'latest', shortId: 'f9e8d7c6', size: '763 MB', containers: 0 },
]
</script>
