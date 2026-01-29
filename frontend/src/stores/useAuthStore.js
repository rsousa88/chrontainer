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
        const form = new URLSearchParams()
        form.set('username', payload.username || '')
        form.set('password', payload.password || '')
        await api.post('/login', form)
        this.user = { username: payload.username }
        return true
      } catch (err) {
        this.error = err
        return false
      } finally {
        this.loading = false
      }
    },
  },
})
