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
          <Input label="Webhook URL" placeholder="https://discord.com/api/webhooks/..." />
          <Input label="Username" placeholder="Chrontainer" />
          <Input label="Avatar URL" placeholder="https://..." />
          <div class="flex gap-3">
            <Button variant="ghost">Send Test</Button>
            <Button variant="primary">Save</Button>
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
          <Input label="Server" placeholder="https://ntfy.sh" />
          <Input label="Topic" placeholder="chrontainer" />
          <Input label="Access Token" placeholder="Optional" />
          <Button variant="ghost">Send Test</Button>
        </div>
      </Card>
      <Card title="Delivery" subtitle="Message preferences">
        <div class="space-y-4">
          <Select label="Priority">
            <option>Normal</option>
            <option>High</option>
          </Select>
          <Select label="Tags">
            <option>system</option>
            <option>containers</option>
          </Select>
        </div>
      </Card>
    </div>

    <div v-else-if="activeTab === 'API Keys'" class="space-y-6">
      <Card title="Create API Key" subtitle="Generate a new access token">
        <div class="grid gap-4 md:grid-cols-3">
          <Input label="Key Name" placeholder="Automation" />
          <Select label="Permissions">
            <option>read</option>
            <option>write</option>
            <option>admin</option>
          </Select>
          <Input label="Expires (days)" placeholder="30" />
        </div>
        <div class="mt-4 flex gap-2">
          <Button variant="primary">Generate</Button>
          <Button variant="ghost">Cancel</Button>
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
        <tr v-for="key in apiKeys" :key="key.id">
          <td class="px-4 py-4 text-sm text-surface-100">{{ key.name }}</td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ key.prefix }}</td>
          <td class="px-4 py-4"><Badge tone="info">{{ key.permissions }}</Badge></td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ key.lastUsed }}</td>
          <td class="px-4 py-4"><Button variant="ghost">Revoke</Button></td>
        </tr>
      </Table>
    </div>

    <div v-else-if="activeTab === 'Webhooks'" class="space-y-6">
      <Card title="Webhook Builder" subtitle="Automate external triggers">
        <div class="grid gap-4 md:grid-cols-2">
          <Input label="Name" placeholder="Restart Sonarr" />
          <Input label="Container ID" placeholder="Optional" />
          <Select label="Action">
            <option>restart</option>
            <option>start</option>
            <option>stop</option>
            <option>update</option>
          </Select>
          <Select label="Lock overrides">
            <option>Unlocked</option>
            <option>Locked</option>
          </Select>
        </div>
        <div class="mt-4 flex gap-2">
          <Button variant="primary">Create Webhook</Button>
          <Button variant="ghost">Cancel</Button>
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
        <tr v-for="hook in webhooks" :key="hook.id">
          <td class="px-4 py-4 text-sm text-surface-100">{{ hook.name }}</td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ hook.action }}</td>
          <td class="px-4 py-4"><Badge :tone="hook.enabled ? 'success' : 'danger'">{{ hook.enabled ? 'Enabled' : 'Disabled' }}</Badge></td>
          <td class="px-4 py-4 text-sm text-surface-300">{{ hook.token }}</td>
          <td class="px-4 py-4"><Button variant="ghost">Manage</Button></td>
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
          <Input label="Current Password" type="password" />
          <Input label="New Password" type="password" />
          <Button variant="primary">Update Password</Button>
        </div>
      </Card>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import Button from '../components/ui/Button.vue'
import Card from '../components/ui/Card.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
import Table from '../components/ui/Table.vue'
import Badge from '../components/ui/Badge.vue'
import HostsView from './HostsView.vue'

const tabs = ['Discord', 'ntfy', 'API Keys', 'Webhooks', 'Docker Hosts', 'Account']
const activeTab = ref('Discord')

const apiKeys = [
  { id: 1, name: 'Automation', prefix: 'chron_abcd', permissions: 'read', lastUsed: '2d ago' },
]

const webhooks = [
  { id: 1, name: 'Restart Sonarr', action: 'restart', enabled: true, token: 'tok_1234' },
]
</script>
