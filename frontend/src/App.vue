<template>
  <AppLayout v-if="!isLogin">
    <RouterView v-slot="{ Component }">
      <Transition name="page" mode="out-in">
        <component :is="Component" />
      </Transition>
    </RouterView>
  </AppLayout>
  <RouterView v-else v-slot="{ Component }">
    <Transition name="page" mode="out-in">
      <component :is="Component" />
    </Transition>
  </RouterView>
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
