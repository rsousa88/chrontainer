import { defineStore } from 'pinia'
import api from '../lib/api'

export const useApiKeyStore = defineStore('apiKeys', {
  state: () => ({
    items: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchKeys() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/keys')
        this.items = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
    async createKey(payload) {
      return api.post('/keys', payload)
    },
    async deleteKey(id) {
      return api.delete(`/keys/${id}`)
    },
  },
})
