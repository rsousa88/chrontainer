import { defineStore } from 'pinia'
import api from '../lib/api'

export const useScheduleStore = defineStore('schedules', {
  state: () => ({
    items: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchSchedules() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/schedules')
        this.items = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
  },
})
