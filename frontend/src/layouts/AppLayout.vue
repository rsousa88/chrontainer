<template>
  <div class="min-h-screen bg-surface-900 text-surface-50">
    <div class="hidden lg:block">
      <Sidebar />
    </div>
    <div class="lg:pl-64">
      <TopBar class="hidden md:flex lg:hidden" />
      <main class="px-4 pb-24 pt-6 sm:px-6 lg:px-10">
        <slot />
      </main>
    </div>
    <BottomNav class="md:hidden" />
  </div>
</template>

<script setup>
import Sidebar from '../components/navigation/Sidebar.vue'
import BottomNav from '../components/navigation/BottomNav.vue'
import TopBar from '../components/navigation/TopBar.vue'
</script>
