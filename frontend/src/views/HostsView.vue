<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Hosts</p>
        <h2 class="text-2xl font-semibold text-surface-50">Docker Hosts</h2>
        <p class="text-sm text-surface-400">Manage host connections and colors.</p>
      </div>
      <div class="flex items-center gap-2">
        <Button variant="ghost" @click="refresh">Refresh</Button>
        <Button variant="primary" @click="openCreate">Add Host</Button>
      </div>
    </div>

    <div v-if="store.loading" class="flex justify-end">
      <Spinner label="Loading hosts" />
    </div>

    <Table>
      <template #head>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Name</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">URL</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Status</th>
        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
      </template>
      <tr v-for="host in store.items" :key="host.id">
        <td class="px-4 py-4 text-sm text-surface-100">{{ host.name }}</td>
        <td class="px-4 py-4 text-sm text-surface-300">{{ host.url }}</td>
        <td class="px-4 py-4">
          <Badge :tone="host.enabled ? 'success' : 'danger'">
            {{ host.enabled ? 'Enabled' : 'Disabled' }}
          </Badge>
        </td>
        <td class="px-4 py-4">
          <div class="flex flex-wrap gap-2">
            <Button variant="ghost" @click="openEdit(host)">Edit</Button>
            <Button variant="ghost" @click="testHost(host)">Test</Button>
            <Button variant="danger" @click="confirmDelete(host)">Delete</Button>
          </div>
        </td>
      </tr>
    </Table>

    <Modal
      :open="modalOpen"
      :title="modalMode === 'create' ? 'Add Host' : 'Edit Host'"
      :subtitle="modalMode === 'create' ? 'Add a Docker host connection.' : 'Update host connection details.'"
      @close="closeModal"
    >
      <div class="grid gap-4 sm:grid-cols-2">
        <Input v-model="form.name" label="Name" placeholder="rpi5" />
        <Input v-model="form.url" label="Docker URL" placeholder="unix:///var/run/docker.sock" />
        <Input v-model="form.color" label="Color" placeholder="#3498db" />
        <label class="flex items-center gap-2 text-sm text-surface-300">
          <input type="checkbox" v-model="form.enabled" class="h-4 w-4 rounded border-surface-600 bg-surface-800" />
          Enabled
        </label>
      </div>
      <template #actions>
        <Button variant="ghost" @click="closeModal">Cancel</Button>
        <Button variant="primary" @click="submitForm">{{ modalMode === 'create' ? 'Add Host' : 'Save Changes' }}</Button>
      </template>
    </Modal>

    <Modal
      :open="deleteModalOpen"
      title="Delete Host"
      subtitle="This action cannot be undone."
      @close="closeDelete"
    >
      <p>Delete host <span class="font-semibold text-surface-100">{{ deleteTarget?.name }}</span>?</p>
      <template #actions>
        <Button variant="ghost" @click="closeDelete">Cancel</Button>
        <Button variant="danger" @click="deleteHost">Delete</Button>
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
import { useHostStore } from '../stores/useHostStore'
import { useToastStore } from '../stores/useToastStore'

const store = useHostStore()
const toastStore = useToastStore()
const refresh = () => store.fetchHosts()

const modalOpen = ref(false)
const deleteModalOpen = ref(false)
const modalMode = ref('create')
const editingId = ref(null)
const deleteTarget = ref(null)
const form = reactive({
  name: '',
  url: '',
  color: '',
  enabled: true,
})

const openCreate = () => {
  modalMode.value = 'create'
  editingId.value = null
  form.name = ''
  form.url = ''
  form.color = ''
  form.enabled = true
  modalOpen.value = true
}

const openEdit = (host) => {
  modalMode.value = 'edit'
  editingId.value = host.id
  form.name = host.name || ''
  form.url = host.url || ''
  form.color = host.color || ''
  form.enabled = !!host.enabled
  modalOpen.value = true
}

const closeModal = () => {
  modalOpen.value = false
}

const submitForm = async () => {
  try {
    if (modalMode.value === 'create') {
      await store.createHost({
        name: form.name,
        url: form.url,
        color: form.color,
      })
      toastStore.push({ title: 'Host added', message: 'Connection saved.' })
    } else if (editingId.value) {
      await store.updateHost(editingId.value, {
        name: form.name,
        url: form.url,
        color: form.color,
        enabled: form.enabled,
      })
      toastStore.push({ title: 'Host updated', message: 'Changes saved.' })
    }
    closeModal()
    refresh()
  } catch (err) {
    toastStore.push({
      title: 'Host update failed',
      message: err?.response?.data?.error || 'Unable to save host.',
      tone: 'danger',
    })
  }
}

const confirmDelete = (host) => {
  deleteTarget.value = host
  deleteModalOpen.value = true
}

const closeDelete = () => {
  deleteModalOpen.value = false
  deleteTarget.value = null
}

const deleteHost = async () => {
  if (!deleteTarget.value) return
  try {
    await store.deleteHost(deleteTarget.value.id)
    toastStore.push({ title: 'Host deleted', message: 'Host removed.' })
    closeDelete()
    refresh()
  } catch (err) {
    toastStore.push({
      title: 'Delete failed',
      message: err?.response?.data?.error || 'Unable to delete host.',
      tone: 'danger',
    })
  }
}

const testHost = async (host) => {
  try {
    const data = await store.testHost(host.id)
    toastStore.push({
      title: data?.success ? 'Host online' : 'Host offline',
      message: data?.message || 'Connection test complete.',
      tone: data?.success ? 'success' : 'danger',
    })
    refresh()
  } catch (err) {
    toastStore.push({
      title: 'Test failed',
      message: err?.response?.data?.error || 'Unable to test host.',
      tone: 'danger',
    })
  }
}

onMounted(() => {
  store.fetchHosts()
})
</script>
