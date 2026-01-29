<template>
  <aside class="fixed inset-y-0 left-0 w-64 border-r border-surface-800 bg-surface-900/95 px-6 py-8">
    <div class="flex items-center gap-3 text-lg font-semibold text-surface-50">
      <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-500/20 text-brand-300">
        <img src="../assets/chrontainer.svg" alt="Chrontainer" class="h-6 w-6" />
      </div>
      <div>
        <div class="leading-tight">Chrontainer</div>
        <div class="text-xs text-surface-400">Frontend v1</div>
      </div>
    </div>

    <nav class="mt-10 space-y-2">
      <RouterLink
        v-for="item in navItems"
        :key="item.path"
        :to="item.path"
        class="group flex items-center gap-3 rounded-xl border border-transparent px-3 py-2 text-sm text-surface-300 transition hover:border-surface-700 hover:bg-surface-800 hover:text-surface-50"
        active-class="border-brand-500/40 bg-brand-500/10 text-surface-50"
      >
        <NavIcon :name="item.icon" />
        <span class="font-medium">{{ item.name }}</span>
      </RouterLink>
    </nav>

    <div class="mt-auto space-y-3 pt-10 text-xs text-surface-500">
      <div>Build: v0.4.17</div>
      <label class="flex items-center gap-2">
        <input type="checkbox" v-model="isLight" class="h-4 w-4 rounded border-surface-600 bg-surface-800" />
        Light mode
      </label>
    </div>
  </aside>
</template>

<script setup>
import { ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { navItems } from './navItems'
import NavIcon from './NavIcon.vue'

const isLight = ref(document.documentElement.dataset.theme === 'light')

watch(isLight, (value) => {
  const theme = value ? 'light' : 'dark'
  document.documentElement.dataset.theme = theme
  localStorage.setItem('theme', theme)
})
</script>
