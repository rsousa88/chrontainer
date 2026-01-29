import { defineStore } from 'pinia'
import api from '../lib/api'

export const useImageStore = defineStore('images', {
  state: () => ({
    items: [],
    loading: false,
    error: null,
  }),
  actions: {
    async fetchImages(refresh = false) {
      this.loading = true
      this.error = null
      try {
        const { data } = await api.get('/images', { params: { refresh: refresh ? 1 : 0 } })
        this.items = data
      } catch (err) {
        this.error = err
      } finally {
        this.loading = false
      }
    },
    async pruneImages(hostId, danglingOnly = false) {
      return api.post('/images/prune', { host_id: hostId, dangling_only: danglingOnly })
    },
    async deleteImage(imageId, hostId, force = false) {
      return api.delete(`/images/${imageId}`, { params: { host_id: hostId }, data: { force } })
    },
  },
})
