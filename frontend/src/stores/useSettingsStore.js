import { defineStore } from 'pinia'
import api from '../lib/api'

export const useSettingsStore = defineStore('settings', {
  state: () => ({
    data: {
      discord_webhook_url: '',
      discord_username: '',
      discord_avatar_url: '',
      ntfy_enabled: 'false',
      ntfy_server: 'https://ntfy.sh',
      ntfy_topic: '',
      ntfy_priority: '3',
      ntfy_access_token: '',
      update_check_enabled: 'true',
      update_check_cron: '0 3 * * *',
    },
    loading: false,
    error: null,
  }),
  actions: {
    async fetchSettings() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/settings')
        this.data = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
    saveDiscord(payload) {
      return api.post('/settings/discord', payload)
    },
    saveNtfy(payload) {
      return api.post('/settings/ntfy', payload)
    },
    saveUpdateCheck(payload) {
      return api.post('/settings/update-check', payload)
    },
    testDiscord() {
      return api.post('/settings/discord/test')
    },
    testNtfy() {
      return api.post('/settings/ntfy/test')
    },
  },
})
