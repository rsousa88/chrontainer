<template>
  <header class="sticky top-0 z-20 flex items-center justify-between border-b border-surface-800 bg-surface-900/90 px-4 py-4 backdrop-blur sm:px-6">
    <div>
      <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Chrontainer</p>
      <h1 class="text-lg font-semibold text-surface-50">{{ title }}</h1>
    </div>
    <div class="flex items-center gap-3">
      <div class="rounded-full border border-surface-700 bg-surface-800 px-3 py-1 text-xs text-surface-300">
        Environment: Local
      </div>
      <button class="rounded-full border border-surface-700 px-3 py-1 text-xs text-surface-300 hover:border-surface-500">
        Profile
      </button>
    </div>
  </header>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { navItems } from './navItems'

const route = useRoute()
const title = computed(() => navItems.find((item) => item.path === route.path)?.name || 'Dashboard')
</script>
