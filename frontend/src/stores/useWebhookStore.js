import { defineStore } from 'pinia'
import api from '../lib/api'

export const useWebhookStore = defineStore('webhooks', {
  state: () => ({
    items: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchWebhooks() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/webhooks')
        this.items = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
    async createWebhook(payload) {
      return api.post('/webhooks', payload)
    },
    async toggleWebhook(id) {
      return api.post(`/webhooks/${id}/toggle`)
    },
    async regenerateToken(id) {
      return api.post(`/webhooks/${id}/regenerate`)
    },
    async deleteWebhook(id) {
      return api.delete(`/webhooks/${id}`)
    },
  },
})
