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
    lastFetchTime: {},  // Track last fetch time per host for caching
    cacheTimeout: 30000,  // 30 seconds cache
  }),
  actions: {
    async fetchImagesForHosts(hostIds = [], refresh = false, preserveExisting = false) {
      this.loading = true
      this.loadingStage = 'loading'
      this.error = null

      // Clear items if not preserving
      if (!preserveExisting) {
        this.items = []
      }

      // Initialize all host statuses to loading
      this.hostStatus = Object.fromEntries(hostIds.map((id) => [Number(id), 'loading']))

      if (!hostIds.length) {
        this.loading = false
        this.loadingStage = 'idle'
        return
      }

      const mergeHostImages = (hostId, images) => {
        // Remove old images for this host and add new ones
        const filtered = this.items.filter((image) => Number(image.host_id) !== Number(hostId))
        this.items = [...filtered, ...images]
      }

      // Launch parallel requests for each host
      const tasks = hostIds.map(async (hostId) => {
        const numericHostId = Number(hostId)

        try {
          // Check cache - skip fetch if cache is fresh and not forcing refresh
          const lastFetch = this.lastFetchTime[numericHostId]
          const now = Date.now()
          if (!refresh && lastFetch && (now - lastFetch) < this.cacheTimeout) {
            // Cache is fresh, mark as done immediately
            this.hostStatus = { ...this.hostStatus, [numericHostId]: 'done' }
            return
          }

          // Fetch from API - only first host gets refresh=1 to clear backend cache
          const { data } = await api.get('/images', {
            params: {
              refresh: refresh ? 1 : 0,
              host_id: hostId,
            },
          })

          // Update cache timestamp
          this.lastFetchTime[numericHostId] = now

          // Merge images for this host
          mergeHostImages(hostId, data || [])
        } catch (err) {
          this.error = err
        } finally {
          // Mark this host as done
          this.hostStatus = { ...this.hostStatus, [numericHostId]: 'done' }
        }
      })

      // Wait for all hosts to complete
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
    clearCache(hostId = null) {
      if (hostId !== null) {
        // Clear cache for specific host
        delete this.lastFetchTime[Number(hostId)]
      } else {
        // Clear all cache
        this.lastFetchTime = {}
      }
    },
  },
})
