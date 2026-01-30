<template>
  <aside class="fixed inset-y-0 left-0 w-64 border-r border-surface-800 bg-surface-900/95 px-6 py-8">
    <div class="flex items-center gap-3 text-lg font-semibold text-surface-50">
      <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-500/20 text-brand-300">
        <img :src="logoUrl" alt="Chrontainer" class="h-6 w-6" />
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
      <div class="flex items-center justify-between gap-2">
        <span>Dark Mode</span>
        <button
          class="relative h-6 w-12 rounded-full border border-surface-700 bg-surface-800 transition"
          :class="isDark ? 'border-brand-400 bg-brand-500/20' : ''"
          @click="toggleTheme"
          aria-label="Toggle theme"
        >
          <span
            class="absolute top-0.5 h-5 w-5 rounded-full bg-surface-200 transition"
            :class="isDark ? 'left-6 bg-brand-400' : 'left-1 bg-surface-200'"
          ></span>
        </button>
      </div>
    </div>
  </aside>
</template>

<script setup>
import { ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { navItems } from './navItems'
import NavIcon from './NavIcon.vue'
import logoUrl from '../../assets/chrontainer.svg'

const isDark = ref(document.documentElement.dataset.theme !== 'light')

const applyTheme = (value) => {
  const theme = value ? 'dark' : 'light'
  document.documentElement.dataset.theme = theme
  localStorage.setItem('theme', theme)
}

const toggleTheme = () => {
  isDark.value = !isDark.value
}

watch(isDark, (value) => {
  applyTheme(value)
})
</script>
