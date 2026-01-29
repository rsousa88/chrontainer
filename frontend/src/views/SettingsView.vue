<template>
  <section class="space-y-6">
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Settings</p>
        <h2 class="text-2xl font-semibold text-surface-50">System Preferences</h2>
        <p class="text-sm text-surface-400">Configure notifications, hosts, and schedules.</p>
      </div>
      <Button variant="primary">Save</Button>
    </div>

    <div class="grid gap-6 lg:grid-cols-2">
      <Card title="Notifications" subtitle="Discord, ntfy, webhooks">
        <div class="space-y-4">
          <Input label="Discord Webhook" placeholder="https://discord.com/api/webhooks/..." />
          <Input label="ntfy Server" placeholder="https://ntfy.sh" />
          <Input label="ntfy Topic" placeholder="alerts" />
        </div>
      </Card>
      <Card title="Update Checks" subtitle="Schedule update discovery">
        <div class="space-y-4">
          <Input label="Cron" placeholder="0 3 * * *" />
          <Select label="Auto-refresh">
            <option>10s</option>
            <option>30s</option>
            <option>60s</option>
          </Select>
        </div>
      </Card>
    </div>
  </section>
</template>

<script setup>
import Card from '../components/ui/Card.vue'
import Button from '../components/ui/Button.vue'
import Input from '../components/ui/Input.vue'
import Select from '../components/ui/Select.vue'
</script>
