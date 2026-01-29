<template>
  <section class="space-y-6">
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Settings</p>
        <h2 class="text-2xl font-semibold text-surface-50">System Preferences</h2>
        <p class="text-sm text-surface-400">Configure notifications, automation, and access.</p>
      </div>
      <Button variant="primary">Save</Button>
    </div>

    <div class="flex flex-wrap gap-2 rounded-2xl border border-surface-800 bg-surface-900/60 p-2">
      <button
        v-for="tab in tabs"
        :key="tab"
        class="rounded-xl px-4 py-2 text-sm font-semibold transition"
        :class="tab === activeTab ? 'bg-brand-500/20 text-brand-200' : 'text-surface-400 hover:text-surface-100'"
        @click="activeTab = tab"
      >
        {{ tab }}
      </button>
    </div>

    <div v-if="activeTab === 'Discord'" class="grid gap-6 lg:grid-cols-2">
      <Card title="Discord Webhook" subtitle="Send notifications to a Discord channel">
        <div class="space-y-4">
          <Input v-model="discord.webhook" label="Webhook URL" placeholder="https://discord.com/api/webhooks/..." />
          <Input label="Username" placeholder="Chrontainer" />
          <Input label="Avatar URL" placeholder="https://..." />
          <div class="flex gap-3">
            <Button variant="ghost" @click="testDiscord">Send Test</Button>
            <Button variant="primary" @click="saveDiscord">Save</Button>
          </div>
        </div>
      </Card>
      <Card title="Events" subtitle="Select which events trigger notifications">
        <div class="grid gap-3 text-sm text-surface-300">
          <label class="flex items-center gap-2"><input type="checkbox" checked /> Container started</label>
          <label class="flex items-center gap-2"><input type="checkbox" checked /> Container stopped</label>
          <label class="flex items-center gap-2"><input type="checkbox" checked /> Container restarted</label>
          <label class="flex items-center gap-2"><input type="checkbox" /> Update available</label>
        </div>
      </Card>
    </div>

    <div v-else-if="activeTab === 'ntfy'" class="grid gap-6 lg:grid-cols-2">
      <Card title="ntfy Settings" subtitle="Push notifications via ntfy.sh">
        <div class="space-y-4">
          <Input v-model="ntfy.server" label="Server" placeholder="https://ntfy.sh" />
          <Input v-model="ntfy.topic" label="Topic" placeholder="chrontainer" />
          <Input label="Access Token" placeholder="Optional" />
          <Button variant="ghost" @click="testNtfy">Send Test</Button>
        </div>
      </Card>
      <Card title="Delivery" subtitle="Message preferences">
        <div class="space-y-4">
          <Select v-model="ntfy.priority" label="Priority">
            <option value="1">Low</option>
            <option value="3">Normal</option>
            <option value="5">High</option>
          </Select>
          <Select label="Tags">
            <option>system</option>
            <option>containers</option>
          </Select>
          <Button variant="primary" @click="saveNtfy">Save</Button>
        </div>
      </Card>
    </div>

    <div v-else-if="activeTab === 'API Keys'" class="space-y-6">
      <Card title="Create API Key" subtitle="Generate a new access token">
        <div class="grid gap-4 md:grid-cols-3">
          <Input v-model="apiKeyForm.name" label="Key Name" placeholder="Automation" />
          <Select v-model="apiKeyForm.permissions" label="Permissions">
            <option value="read">read</option>
            <option value="write">write</option>
            <option value="admin">admin</option>
          </Select>
          <Input v-model="apiKeyForm.expiresDays" label="Expires (days)" placeholder="30" />
        </div>
        <div class="mt-4 flex gap-2">
          <Button variant="primary" @click="createKey">Generate</Button>
          <Button variant="ghost" @click="resetKeyForm">Cancel</Button>
        </div>
      </Card>

      <Table>
        <template #head>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Name</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Prefix</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Permissions</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Last Used</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
        </template>
        <tr v-for="key in apiKeyStore.items" :key="key.id">
          <td class="px-4 py-4 text-sm text-surface-100">{{ key.name }}</td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ key.key_prefix }}</td>
          <td class="px-4 py-4"><Badge tone="info">{{ key.permissions }}</Badge></td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ key.last_used || '—' }}</td>
          <td class="px-4 py-4"><Button variant="ghost" @click="deleteKey(key.id)">Revoke</Button></td>
        </tr>
      </Table>
    </div>

    <div v-else-if="activeTab === 'Webhooks'" class="space-y-6">
      <Card title="Webhook Builder" subtitle="Automate external triggers">
        <div class="grid gap-4 md:grid-cols-2">
          <Input v-model="webhookForm.name" label="Name" placeholder="Restart Sonarr" />
          <Input v-model="webhookForm.containerId" label="Container ID" placeholder="Optional" />
          <Select v-model="webhookForm.action" label="Action">
            <option>restart</option>
            <option>start</option>
            <option>stop</option>
            <option>update</option>
          </Select>
          <Select v-model="webhookForm.locked" label="Lock overrides">
            <option value="false">Unlocked</option>
            <option value="true">Locked</option>
          </Select>
        </div>
        <div class="mt-4 flex gap-2">
          <Button variant="primary" @click="createWebhook">Create Webhook</Button>
          <Button variant="ghost" @click="resetWebhookForm">Cancel</Button>
        </div>
      </Card>
      <Table>
        <template #head>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Name</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Action</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Status</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Token</th>
          <th class="px-4 py-3 text-xs font-semibold uppercase tracking-widest">Actions</th>
        </template>
        <tr v-for="hook in webhookStore.items" :key="hook.id">
          <td class="px-4 py-4 text-sm text-surface-100">{{ hook.name }}</td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ hook.action }}</td>
          <td class="px-4 py-4"><Badge :tone="hook.enabled ? 'success' : 'danger'">{{ hook.enabled ? 'Enabled' : 'Disabled' }}</Badge></td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ hook.token }}</td>
          <td class="px-4 py-4 flex gap-2">
            <Button variant="ghost" @click="toggleWebhook(hook.id)">Toggle</Button>
            <Button variant="ghost" @click="regenerateWebhook(hook.id)">New Token</Button>
            <Button variant="ghost" @click="deleteWebhook(hook.id)">Delete</Button>
          </td>
        </tr>
      </Table>
    </div>

    <div v-else-if="activeTab === 'Docker Hosts'" class="space-y-6">
      <HostsView />
    </div>

    <div v-else-if="activeTab === 'Account'" class="grid gap-6 lg:grid-cols-2">
      <Card title="Profile" subtitle="User details and access">
        <div class="space-y-4">
          <Input label="Username" placeholder="admin" />
          <Input label="Role" placeholder="admin" />
        </div>
      </Card>
      <Card title="Security" subtitle="Update your password">
        <div class="space-y-4">
          <Input v-model="passwordForm.current" label="Current Password" type="password" />
          <Input v-model="passwordForm.next" label="New Password" type="password" />
          <Input v-model="passwordForm.confirm" label="Confirm Password" type="password" />
          <Button variant="primary" @click="changePassword">Update Password</Button>
        </div>
      </Card>
    </div>
  </section>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import Table from '../components/ui/Table.vue'
import Badge from '../components/ui/Badge.vue'
import HostsView from './HostsView.vue'
import { useSettingsStore } from '../stores/useSettingsStore'
import { useApiKeyStore } from '../stores/useApiKeyStore'
import { useWebhookStore } from '../stores/useWebhookStore'
import { useToastStore } from '../stores/useToastStore'
import api from '../lib/api'

const tabs = ['Discord', 'ntfy', 'API Keys', 'Webhooks', 'Docker Hosts', 'Account']
const activeTab = ref('Discord')

const settingsStore = useSettingsStore()
const apiKeyStore = useApiKeyStore()
const webhookStore = useWebhookStore()
const toastStore = useToastStore()

const discord = reactive({ webhook: '' })
const ntfy = reactive({ server: 'https://ntfy.sh', topic: '', priority: '3' })
const apiKeyForm = reactive({ name: '', permissions: 'read', expiresDays: '' })
const webhookForm = reactive({ name: '', containerId: '', action: 'restart', locked: 'false' })
const passwordForm = reactive({ current: '', next: '', confirm: '' })

const saveDiscord = async () => {
  await settingsStore.saveDiscord(discord.webhook)
  toastStore.push({ title: 'Discord saved', message: 'Webhook updated.' })
}

const saveNtfy = async () => {
  await settingsStore.saveNtfy({
    enabled: true,
    server: ntfy.server,
    topic: ntfy.topic,
    priority: parseInt(ntfy.priority, 10),
  })
  toastStore.push({ title: 'ntfy saved', message: 'Settings updated.' })
}

const testDiscord = async () => {
  await settingsStore.testDiscord()
  toastStore.push({ title: 'Discord test sent', message: 'Check your channel.' })
}

const testNtfy = async () => {
  await settingsStore.testNtfy()
  toastStore.push({ title: 'ntfy test sent', message: 'Check your device.' })
}

const createKey = async () => {
  const payload = {\n    name: apiKeyForm.name,\n    permissions: apiKeyForm.permissions,\n    expires_days: apiKeyForm.expiresDays ? Number(apiKeyForm.expiresDays) : undefined,\n  }\n  await apiKeyStore.createKey(payload)\n  await apiKeyStore.fetchKeys()\n  toastStore.push({ title: 'API key created', message: 'Key generated successfully.' })\n  resetKeyForm()\n}\n\nconst resetKeyForm = () => {\n  apiKeyForm.name = ''\n  apiKeyForm.permissions = 'read'\n  apiKeyForm.expiresDays = ''\n}\n\nconst deleteKey = async (id) => {\n  await apiKeyStore.deleteKey(id)\n  await apiKeyStore.fetchKeys()\n  toastStore.push({ title: 'API key revoked', message: 'Key removed.' })\n}\n\nconst createWebhook = async () => {\n  await webhookStore.createWebhook({\n    name: webhookForm.name,\n    container_id: webhookForm.containerId || undefined,\n    action: webhookForm.action,\n    locked: webhookForm.locked === 'true',\n  })\n  await webhookStore.fetchWebhooks()\n  toastStore.push({ title: 'Webhook created', message: 'Webhook is ready.' })\n  resetWebhookForm()\n}\n\nconst resetWebhookForm = () => {\n  webhookForm.name = ''\n  webhookForm.containerId = ''\n  webhookForm.action = 'restart'\n  webhookForm.locked = 'false'\n}\n\nconst toggleWebhook = async (id) => {\n  await webhookStore.toggleWebhook(id)\n  await webhookStore.fetchWebhooks()\n}\n\nconst regenerateWebhook = async (id) => {\n  await webhookStore.regenerateToken(id)\n  await webhookStore.fetchWebhooks()\n  toastStore.push({ title: 'Token regenerated', message: 'New webhook token created.' })\n}\n\nconst deleteWebhook = async (id) => {\n  await webhookStore.deleteWebhook(id)\n  await webhookStore.fetchWebhooks()\n  toastStore.push({ title: 'Webhook deleted', message: 'Webhook removed.' })\n}\n\nconst changePassword = async () => {\n  await api.post('/user/change-password', {\n    current_password: passwordForm.current,\n    new_password: passwordForm.next,\n    confirm_password: passwordForm.confirm,\n  })\n  toastStore.push({ title: 'Password updated', message: 'Credentials updated.' })\n  passwordForm.current = ''\n  passwordForm.next = ''\n  passwordForm.confirm = ''\n}\n+\n+onMounted(async () => {\n+  await settingsStore.fetchSettings()\n+  await apiKeyStore.fetchKeys()\n+  await webhookStore.fetchWebhooks()\n+\n+  discord.webhook = settingsStore.data.discord_webhook_url || ''\n+  ntfy.server = settingsStore.data.ntfy_server || 'https://ntfy.sh'\n+  ntfy.topic = settingsStore.data.ntfy_topic || ''\n+  ntfy.priority = settingsStore.data.ntfy_priority || '3'\n+})\n </script>
</script>
