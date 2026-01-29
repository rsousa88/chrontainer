import { defineStore } from 'pinia'
import api from '../lib/api'

export const useLogStore = defineStore('logs', {
  state: () => ({
    entries: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchLogs() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/logs')
        this.entries = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
  },
})
