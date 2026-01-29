<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Images</p>
        <h2 class="text-2xl font-semibold text-surface-50">Image Library</h2>
        <p class="text-sm text-surface-400">Review and prune unused images.</p>
      </div>
      <div class="flex items-center gap-2">
        <Button variant="ghost" :disabled="controlsDisabled" @click="refresh">Refresh</Button>
        <Button variant="danger" :disabled="controlsDisabled" @click="notify">Prune Unused</Button>
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

    <div v-if="imageStore.loading || imageStore.pendingCounts" class="flex justify-end">
      <Spinner label="Loading images" />
    </div>

    <Table>
      <template #head>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Host</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Repository</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Tag</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Image ID</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Size</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Containers</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
      </template>
      <tr v-for="image in imageStore.items" :key="image.id">
        <td class="px-4 py-4">
          <Badge :tone="image.host_name ? 'info' : 'neutral'">{{ image.host_name || image.host || '—' }}</Badge>
        </td>
        <td class="px-4 py-4 text-sm text-surface-100">{{ image.repository || image.repo || image.repo_name || 'unknown' }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ image.tag || image.image_tag || 'latest' }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ image.short_id || image.shortId || image.id?.slice?.(7, 17) }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ formatSize(image.size_bytes ?? image.size) }}</td>
        <td class="px-4 py-4">
          <Badge :tone="displayCount(image) === '-' ? 'neutral' : (displayCount(image) === 0 ? 'warning' : 'info')">
            {{ displayCount(image) }}
          </Badge>
        </td>
        <td class="px-4 py-4">
          <Button variant="ghost" :disabled="controlsDisabled" @click="deleteImage(image)">Delete</Button>
        </td>
      </tr>
    </Table>
  </section>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import Card from '../components/ui/Card.vue'
import Table from '../components/ui/Table.vue'
import Badge from '../components/ui/Badge.vue'
import Button from '../components/ui/Button.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import Spinner from '../components/ui/Spinner.vue'
import { useToastStore } from '../stores/useToastStore'
import { useImageStore } from '../stores/useImageStore'

const filters = ref({
  query: '',
  host: '',
  unused: '',
})

const toastStore = useToastStore()
const imageStore = useImageStore()

const controlsDisabled = computed(() => imageStore.loading || imageStore.pendingCounts)

const formatSize = (bytes) => {
  const value = typeof bytes === 'number' ? bytes : Number(bytes)
  if (!Number.isFinite(value) || value <= 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex += 1
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unitIndex]}`
}

const displayCount = (image) => {
  if (imageStore.pendingCounts) return '-'
  return image.containers ?? image.containers_count ?? 0
}

const refresh = () => imageStore.fetchImages(true)

const notify = async () => {
  try {
    await imageStore.pruneImages(1, true)
    toastStore.push({ title: 'Prune queued', message: 'Unused images will be removed.' })
    refresh()
  } catch (err) {
    toastStore.push({ title: 'Prune failed', message: 'Unable to prune images.' })
  }
}

const deleteImage = async (image) => {
  try {
    await imageStore.deleteImage(image.id, image.host_id || 1, false)
    toastStore.push({ title: 'Image deleted', message: 'Image removed successfully.' })
    refresh()
  } catch (err) {
    toastStore.push({ title: 'Delete failed', message: 'Unable to remove image.' })
  }
}

onMounted(() => {
  imageStore.fetchImages()
})
</script>
