<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Schedules</p>
        <h2 class="text-2xl font-semibold text-surface-50">Automation</h2>
        <p class="text-sm text-surface-400">Manage cron and one-time schedules.</p>
      </div>
      <div class="flex items-center gap-2">
        <Button variant="ghost" @click="refresh">Refresh</Button>
        <Button variant="primary">New Schedule</Button>
      </div>
    </div>

    <div v-if="store.loading" class="flex justify-end">
      <Spinner label="Loading schedules" />
    </div>

    <Table>
      <template #head>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Container</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Action</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Cron</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Status</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
      </template>
      <tr v-for="schedule in store.items" :key="schedule.id">
        <td class="px-4 py-4 text-sm text-surface-100">{{ schedule.container_name || schedule.container }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ schedule.action }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ schedule.cron_expression || schedule.cron }}</td>
        <td class="px-4 py-4">
          <Badge :tone="schedule.enabled ? 'success' : 'danger'">
            {{ schedule.enabled ? 'Enabled' : 'Disabled' }}
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
import { onMounted } from 'vue'
import Table from '../components/ui/Table.vue'
import Button from '../components/ui/Button.vue'
import Badge from '../components/ui/Badge.vue'
import Spinner from '../components/ui/Spinner.vue'
import { useScheduleStore } from '../stores/useScheduleStore'

const store = useScheduleStore()
const refresh = () => store.fetchSchedules()

onMounted(() => {
  store.fetchSchedules()
})
</script>
