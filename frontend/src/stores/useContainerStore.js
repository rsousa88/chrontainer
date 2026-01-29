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
        let items = data

        try {
          const { data: stats } = await api.get('/containers/stats')
          const statsMap = stats || {}
          items = items.map((container) => {
            const hostId = container.host_id || container.hostId || 1
            const key = `${container.id}_${hostId}`
            const metrics = statsMap[key]
            const cpuValue = metrics?.cpu_percent
            const memoryValue = metrics?.memory_mb
            return {
              ...container,
              host: container.host_name || container.host || container.hostName || '—',
              cpu: cpuValue === 0 || cpuValue ? `${cpuValue}%` : '—',
              memory: memoryValue === 0 || memoryValue ? `${memoryValue} MB` : '—',
            }
          })
        } catch (err) {
          items = items.map((container) => ({
            ...container,
            host: container.host_name || container.host || container.hostName || '—',
            cpu: container.cpu || '—',
            memory: container.memory || '—',
          }))
        }

        this.items = items
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
  },
})
