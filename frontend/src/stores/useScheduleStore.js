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
    async createSchedule(payload) {
      const { data } = await api.post('/schedule', payload)
      return data
    },
    async updateSchedule(id, payload) {
      const { data } = await api.put(`/schedule/${id}`, payload)
      return data
    },
    async deleteSchedule(id) {
      const { data } = await api.delete(`/schedule/${id}`)
      return data
    },
    async toggleSchedule(id) {
      const { data } = await api.post(`/schedule/${id}/toggle`)
      return data
    },
  },
})
