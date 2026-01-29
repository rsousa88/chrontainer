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
        <Button variant="primary" @click="openCreate">New Schedule</Button>
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
          <div class="flex flex-wrap gap-2">
            <Button variant="ghost" @click="openEdit(schedule)">Edit</Button>
            <Button variant="ghost" @click="toggle(schedule)">{{ schedule.enabled ? 'Disable' : 'Enable' }}</Button>
            <Button variant="danger" @click="confirmDelete(schedule)">Delete</Button>
          </div>
        </td>
      </tr>
    </Table>

    <Modal
      :open="modalOpen"
      :title="modalMode === 'create' ? 'New Schedule' : 'Edit Schedule'"
      :subtitle="modalMode === 'create' ? 'Create a new automation schedule.' : 'Update schedule details.'"
      @close="closeModal"
    >
      <div class="grid gap-4 md:grid-cols-2">
        <Input v-model="form.containerId" label="Container ID" placeholder="abc123..." />
        <Input v-model="form.containerName" label="Container Name" placeholder="sonarr" />
        <Select v-model="form.hostId" label="Host">
          <option v-for="host in hostStore.items" :key="host.id" :value="host.id">
            {{ host.name }}
          </option>
        </Select>
        <Select v-model="form.action" label="Action">
          <option value="restart">restart</option>
          <option value="start">start</option>
          <option value="stop">stop</option>
          <option value="pause">pause</option>
          <option value="unpause">unpause</option>
          <option value="update">update</option>
        </Select>
        <label class="flex items-center gap-2 text-sm text-surface-300">
          <input type="checkbox" v-model="form.oneTime" class="h-4 w-4 rounded border-surface-600 bg-surface-800" />
          One-time schedule
        </label>
        <Input
          v-model="form.runAt"
          label="Run At"
          type="datetime-local"
          :disabled="!form.oneTime"
        />
        <Input
          v-model="form.cron"
          label="Cron Expression"
          placeholder="0 2 * * *"
          :disabled="form.oneTime"
        />
      </div>
      <template #actions>
        <Button variant="ghost" @click="closeModal">Cancel</Button>
        <Button variant="primary" @click="submitForm">{{ modalMode === 'create' ? 'Create' : 'Save' }}</Button>
      </template>
    </Modal>

    <Modal
      :open="deleteModalOpen"
      title="Delete Schedule"
      subtitle="This action cannot be undone."
      @close="closeDelete"
    >
      <p>Delete schedule for <span class="font-semibold text-surface-100">{{ deleteTarget?.container_name || deleteTarget?.container }}</span>?</p>
      <template #actions>
        <Button variant="ghost" @click="closeDelete">Cancel</Button>
        <Button variant="danger" @click="deleteSchedule">Delete</Button>
      </template>
    </Modal>
  </section>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import Table from '../components/ui/Table.vue'
import Button from '../components/ui/Button.vue'
import Badge from '../components/ui/Badge.vue'
import Spinner from '../components/ui/Spinner.vue'
import Modal from '../components/ui/Modal.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import { useScheduleStore } from '../stores/useScheduleStore'
import { useHostStore } from '../stores/useHostStore'
import { useToastStore } from '../stores/useToastStore'

const store = useScheduleStore()
const hostStore = useHostStore()
const toastStore = useToastStore()
const refresh = () => store.fetchSchedules()

const modalOpen = ref(false)
const deleteModalOpen = ref(false)
const modalMode = ref('create')
const editingId = ref(null)
const deleteTarget = ref(null)
const form = reactive({
  containerId: '',
  containerName: '',
  hostId: 1,
  action: 'restart',
  cron: '',
  oneTime: false,
  runAt: '',
})

const openCreate = () => {
  modalMode.value = 'create'
  editingId.value = null
  form.containerId = ''
  form.containerName = ''
  form.hostId = hostStore.items[0]?.id || 1
  form.action = 'restart'
  form.cron = ''
  form.oneTime = false
  form.runAt = ''
  modalOpen.value = true
}

const openEdit = (schedule) => {
  modalMode.value = 'edit'
  editingId.value = schedule.id
  form.containerId = schedule.container_id || schedule.containerId || ''
  form.containerName = schedule.container_name || schedule.container || ''
  form.hostId = schedule.host_id || schedule.hostId || hostStore.items[0]?.id || 1
  form.action = schedule.action || 'restart'
  form.cron = schedule.cron_expression || schedule.cron || ''
  form.oneTime = !!schedule.one_time || !!schedule.oneTime
  form.runAt = schedule.run_at || schedule.runAt || ''
  modalOpen.value = true
}

const closeModal = () => {
  modalOpen.value = false
}

const normalizeRunAt = () => {
  if (!form.runAt) return null
  const date = new Date(form.runAt)
  return Number.isNaN(date.getTime()) ? form.runAt : date.toISOString()
}

const submitForm = async () => {
  try {
    const payload = {
      host_id: form.hostId,
      container_id: form.containerId,
      container_name: form.containerName,
      action: form.action,
      cron_expression: form.oneTime ? '' : form.cron,
      one_time: form.oneTime,
      run_at: form.oneTime ? normalizeRunAt() : null,
    }
    if (modalMode.value === 'create') {
      await store.createSchedule(payload)
      toastStore.push({ title: 'Schedule created', message: 'Schedule saved.' })
    } else if (editingId.value) {
      await store.updateSchedule(editingId.value, payload)
      toastStore.push({ title: 'Schedule updated', message: 'Changes saved.' })
    }
    closeModal()
    refresh()
  } catch (err) {
    toastStore.push({
      title: 'Schedule failed',
      message: err?.response?.data?.error || 'Unable to save schedule.',
      tone: 'danger',
    })
  }
}

const confirmDelete = (schedule) => {
  deleteTarget.value = schedule
  deleteModalOpen.value = true
}

const closeDelete = () => {
  deleteModalOpen.value = false
  deleteTarget.value = null
}

const deleteSchedule = async () => {
  if (!deleteTarget.value) return
  try {
    await store.deleteSchedule(deleteTarget.value.id)
    toastStore.push({ title: 'Schedule deleted', message: 'Schedule removed.' })
    closeDelete()
    refresh()
  } catch (err) {
    toastStore.push({
      title: 'Delete failed',
      message: err?.response?.data?.error || 'Unable to delete schedule.',
      tone: 'danger',
    })
  }
}

const toggle = async (schedule) => {
  try {
    await store.toggleSchedule(schedule.id)
    toastStore.push({ title: 'Schedule updated', message: 'Status toggled.' })
    refresh()
  } catch (err) {
    toastStore.push({
      title: 'Toggle failed',
      message: err?.response?.data?.error || 'Unable to update schedule.',
      tone: 'danger',
    })
  }
}

onMounted(() => {
  hostStore.fetchHosts()
  store.fetchSchedules()
})
</script>
