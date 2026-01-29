import { defineStore } from 'pinia'
import api from '../lib/api'

export const useContainerStore = defineStore('containers', {
  state: () => ({
    items: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchContainers() {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/containers')
        this.items = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
  },
})
