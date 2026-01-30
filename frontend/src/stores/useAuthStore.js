import { defineStore } from 'pinia'
import api from '../lib/api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    loading: false,
    error: null,
  }),
  actions: {
    async fetchUser() {
      try {
        const { data } = await api.get('/user')
        if (data && typeof data === 'object' && data.username) {
          this.user = data
        } else {
          this.user = null
        }
      } catch (err) {
        this.user = null
      }
    },
    async login(payload) {
      this.loading = true
      this.error = null
      try {
        const form = new URLSearchParams()
        form.set('username', payload.username || '')
        form.set('password', payload.password || '')
        await api.post('/login', form)
        await this.fetchUser()
        return true
      } catch (err) {
        this.error = err?.response?.data?.error || 'Login failed'
        return false
      } finally {
        this.loading = false
      }
    },
    async logout() {
      try {
        await api.post('/logout')
      } finally {
        this.user = null
      }
    },
  },
})
