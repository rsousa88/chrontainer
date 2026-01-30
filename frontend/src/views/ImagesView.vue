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
        <Button variant="danger" :disabled="controlsDisabled || !pruneHostId" @click="notify">Prune Unused</Button>
      </div>
    </div>

    <Card :class="controlsDisabled ? 'opacity-70 pointer-events-none' : ''">
      <div class="grid gap-4 md:grid-cols-3">
        <Input v-model="filters.query" label="Search" placeholder="Filter images" />
        <Select v-model="filters.host" label="Host">
          <option value="">All Hosts</option>
          <option v-for="host in availableHosts" :key="host.id" :value="String(host.id)">
            {{ host.name }}
          </option>
        </Select>
        <Select v-model="filters.unused" label="Unused">
          <option value="">All</option>
          <option value="true">Unused only</option>
        </Select>
      </div>
    </Card>

    <div v-if="showSpinner" class="flex justify-end">
      <Spinner :label="spinnerLabel" />
    </div>

    <div :class="controlsDisabled ? 'opacity-70 pointer-events-none' : ''">
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
      <tr v-for="image in filteredImages" :key="image.id">
        <td class="px-4 py-4">
          <span
            class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold"
            :style="{
              backgroundColor: image.host_color || '#2c3542',
              color: image.host_text_color || '#f8fafc'
            }"
          >
            {{ image.host_name || image.host || '—' }}
          </span>
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
    </div>
  </section>
</template>

<script setup>
import { computed, ref, onMounted, watch } from 'vue'
import Card from '../components/ui/Card.vue'
import Table from '../components/ui/Table.vue'
import Badge from '../components/ui/Badge.vue'
import Button from '../components/ui/Button.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import Spinner from '../components/ui/Spinner.vue'
import { useToastStore } from '../stores/useToastStore'
import { useImageStore } from '../stores/useImageStore'
import { useHostStore } from '../stores/useHostStore'

const filters = ref({
  query: '',
  host: '',
  unused: '',
})

const toastStore = useToastStore()
const imageStore = useImageStore()
const hostStore = useHostStore()

const refreshing = ref(false)
const pendingCounts = computed(() => imageStore.loadingStage === 'loading' || refreshing.value)
const controlsDisabled = computed(() => imageStore.loadingStage !== 'idle' || imageStore.pruning || pendingCounts.value)
const isHostEnabled = (host) => host.enabled !== false && host.enabled !== 0 && host.enabled !== '0'
const availableHosts = computed(() => hostStore.items.filter((host) => isHostEnabled(host)))
const showSpinner = computed(() => imageStore.loadingStage === 'loading' || imageStore.pruning)
const spinnerLabel = computed(() => (imageStore.pruning ? 'Pruning unused images' : 'Loading images'))
const pruneHostId = computed(() => {
  const allowedIds = new Set(availableHosts.value.map((host) => Number(host.id)))
  if (filters.value.host && allowedIds.has(Number(filters.value.host))) {
    return Number(filters.value.host)
  }
  const firstHost = availableHosts.value[0]
  return firstHost ? Number(firstHost.id) : null
})

const filteredImages = computed(() => {
  const query = filters.value.query.trim().toLowerCase()
  const hostFilter = filters.value.host
  const unusedOnly = filters.value.unused === 'true'

  return imageStore.items.filter((image) => {
    if (hostFilter && String(image.host_id) !== hostFilter) return false
    if (unusedOnly && Number(image.containers || 0) !== 0) return false
    if (query) {
      const haystack = `${image.repository || ''} ${image.tag || ''} ${image.short_id || ''}`.toLowerCase()
      if (!haystack.includes(query)) return false
    }
    return true
  })
})

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
  if (refreshing.value) return '-'
  if (imageStore.loadingStage === 'loading') {
    const status = imageStore.hostStatus[Number(image?.host_id)]
    if (status !== 'done') return '-'
  }
  if (image?.containers_pending) return '-'
  return image.containers ?? image.containers_count ?? 0
}

const refresh = async () => {
  const hostIds = availableHosts.value.map((host) => host.id)
  refreshing.value = true
  try {
    await imageStore.fetchImagesForHosts(hostIds, true, true)
  } finally {
    refreshing.value = false
  }
}

const notify = async () => {
  if (!pruneHostId.value) {
    toastStore.push({ title: 'Prune unavailable', message: 'Select a valid host first.', tone: 'warning' })
    return
  }
  try {
    const response = await imageStore.pruneImages(pruneHostId.value, false)
    const deleted = response?.data?.images_deleted || []
    const reclaimed = response?.data?.reclaimed || 0
    if (!deleted.length) {
      toastStore.push({ title: 'No unused images', message: 'No unused images were found to prune.', tone: 'warning' })
    } else {
      toastStore.push({
        title: 'Prune completed',
        message: `Removed ${deleted.length} image(s), reclaimed ${formatSize(reclaimed)}.`,
      })
    }
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

onMounted(async () => {
  await hostStore.fetchHosts()
  const hostIds = availableHosts.value.map((host) => host.id)
  refreshing.value = true
  try {
    await imageStore.fetchImagesForHosts(hostIds, false)
  } finally {
    refreshing.value = false
  }
})

watch(
  availableHosts,
  (hosts) => {
    if (filters.value.host && !hosts.find((host) => String(host.id) === filters.value.host)) {
      filters.value.host = ''
    }
    if (!hosts.length) return
    if (imageStore.items.length) return
    if (imageStore.loading || refreshing.value) return
    refreshing.value = true
    imageStore.fetchImagesForHosts(hosts.map((host) => host.id), false).finally(() => {
      refreshing.value = false
    })
  },
  { immediate: true }
)
</script>
