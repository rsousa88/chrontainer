<template>
  <div class="fixed right-6 top-6 z-50 space-y-3">
    <transition-group name="toast" tag="div">
      <div
        v-for="toast in toasts"
        :key="toast.id"
        class="rounded-xl border px-4 py-3 text-sm text-surface-100 shadow-xl"
        :class="toastClass(toast.tone)"
      >
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="font-semibold">{{ toast.title }}</p>
            <p class="text-xs text-surface-400">{{ toast.message }}</p>
          </div>
          <button class="text-surface-400 hover:text-surface-200" @click="remove(toast.id)">✕</button>
        </div>
      </div>
    </transition-group>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useToastStore } from '../../stores/useToastStore'

const store = useToastStore()
const toasts = computed(() => store.toasts)

const remove = (id) => store.remove(id)

const toastClass = (tone) => {
  if (tone === 'danger') {
    return 'border-rose-500/60 bg-rose-500/10'
  }
  if (tone === 'success') {
    return 'border-emerald-500/60 bg-emerald-500/10'
  }
  return 'border-surface-800 bg-surface-900/90'
}
</script>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.3s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
</style>
