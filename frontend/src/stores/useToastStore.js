import { defineStore } from 'pinia'

let nextId = 1

export const useToastStore = defineStore('toasts', {
  state: () => ({
    toasts: [],
  }),
  actions: {
    push({ title, message }) {
      const id = nextId++
      this.toasts.push({ id, title, message })
      setTimeout(() => this.remove(id), 5000)
    },
    remove(id) {
      this.toasts = this.toasts.filter((toast) => toast.id !== id)
    },
  },
})
