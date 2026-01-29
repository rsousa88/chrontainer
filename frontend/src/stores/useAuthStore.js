import { defineStore } from 'pinia'
import api from '../lib/api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    loading: false,
    error: null,
  }),
  actions: {
    async login(payload) {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.post('/login', payload)
        this.user = data?.user || null
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
  },
})
