<template>
  <nav class="fixed inset-x-0 bottom-0 z-20 border-t border-surface-800 bg-surface-900/95 px-4 py-3 backdrop-blur">
    <div class="mx-auto flex max-w-md items-center justify-between">
      <RouterLink
        v-for="item in navItems"
        :key="item.path"
        :to="item.path"
        class="flex flex-col items-center gap-1 text-[11px] text-surface-400"
        active-class="text-brand-300"
      >
        <NavIcon :name="item.icon" />
        <span>{{ item.name }}</span>
      </RouterLink>
    </div>
  </nav>
</template>

<script setup>
import { RouterLink } from 'vue-router'
import { navItems } from './navItems'
import NavIcon from './NavIcon.vue'
</script>
