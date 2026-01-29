import { defineStore } from 'pinia'
import api from '../lib/api'

export const useHostStore = defineStore('hosts', {
  state: () => ({
    items: [],
    metrics: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchHosts() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/hosts')
        this.items = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
    async fetchMetrics() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/hosts/metrics')
        this.metrics = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
    async createHost(payload) {
      const { data } = await api.post('/hosts', payload)
      return data
    },
    async updateHost(id, payload) {
      const { data } = await api.put(`/hosts/${id}`, payload)
      return data
    },
    async deleteHost(id) {
      const { data } = await api.delete(`/hosts/${id}`)
      return data
    },
    async testHost(id) {
      const { data } = await api.post(`/hosts/${id}/test`)
      return data
    },
  },
})
