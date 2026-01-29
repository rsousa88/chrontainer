<template>
  <AppLayout>
    <RouterView />
  </AppLayout>
  <ToastContainer />
</template>

<script setup>
import { RouterView } from 'vue-router'
import AppLayout from './layouts/AppLayout.vue'
import ToastContainer from './components/feedback/ToastContainer.vue'
</script>
