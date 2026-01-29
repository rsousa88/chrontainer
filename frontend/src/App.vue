<template>
  <AppLayout v-if="!isLogin">
    <Transition name="page" mode="out-in">
      <RouterView />
    </Transition>
  </AppLayout>
  <Transition v-else name="page" mode="out-in">
    <RouterView />
  </Transition>
  <ToastContainer />
</template>

<script setup>
import { RouterView } from 'vue-router'
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import AppLayout from './layouts/AppLayout.vue'
import ToastContainer from './components/feedback/ToastContainer.vue'

const route = useRoute()
const isLogin = computed(() => route.name === 'login')
</script>
