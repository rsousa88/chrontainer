import { defineStore } from 'pinia'
import api from '../lib/api'

export const useImageStore = defineStore('images', {
  state: () => ({
    items: [],
    loading: false,
    error: null,
    hostStatus: {},
    loadingStage: 'idle', // idle | loading | pruning
    pruning: false,
  }),
  actions: {
    async fetchImagesForHosts(hostIds = [], refresh = false, preserveExisting = false) {
      this.loading = true
      this.loadingStage = 'loading'
      this.error = null
      if (!preserveExisting) {
        this.items = []
      }
      this.hostStatus = Object.fromEntries(hostIds.map((id) => [Number(id), 'loading']))

      if (!hostIds.length) {
        this.loading = false
        this.loadingStage = 'idle'
        return
      }

      const mergeHostImages = (hostId, images) => {
        const filtered = this.items.filter((image) => Number(image.host_id) !== Number(hostId))
        this.items = [...filtered, ...images]
      }

      const tasks = hostIds.map(async (hostId, index) => {
        try {
          const { data } = await api.get('/images', {
            params: { refresh: refresh && index === 0 ? 1 : 0, host_id: hostId, ts: Date.now() },
          })
          mergeHostImages(hostId, data || [])
        } catch (err) {
          this.error = err
        } finally {
          this.hostStatus = { ...this.hostStatus, [Number(hostId)]: 'done' }
        }
      })

      await Promise.all(tasks)
      this.loading = false
      this.loadingStage = 'idle'
    },
    async pruneImages(hostId, danglingOnly = false) {
      this.pruning = true
      this.loadingStage = 'pruning'
      try {
        return await api.post('/images/prune', { host_id: hostId, dangling_only: danglingOnly })
      } finally {
        this.pruning = false
        if (!this.loading) {
          this.loadingStage = 'idle'
        }
      }
    },
    async deleteImage(imageId, hostId, force = false) {
      return api.delete(`/images/${imageId}`, { params: { host_id: hostId }, data: { force } })
    },
  },
})
