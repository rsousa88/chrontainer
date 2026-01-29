<template>
  <div class="flex min-h-screen items-center justify-center bg-surface-950 px-6">
    <div class="w-full max-w-md rounded-2xl border border-surface-800 bg-surface-900/80 p-8">
      <div class="mb-6 text-center">
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Chrontainer</p>
        <h2 class="text-2xl font-semibold text-surface-50">Sign in</h2>
        <p class="text-sm text-surface-400">Welcome back to your container hub.</p>
      </div>
      <div class="space-y-4">
        <Input v-model="form.username" label="Username" placeholder="admin" />
        <Input v-model="form.password" label="Password" type="password" placeholder="••••••••" />
      </div>
      <div class="mt-6">
        <Button variant="primary" full-width @click="submit">
          <span v-if="store.loading">Signing in...</span>
          <span v-else>Login</span>
        </Button>
      </div>
      <p v-if="store.error" class="mt-4 text-xs text-rose-400">{{ store.error }}</p>
    </div>
  </div>
</template>

<script setup>
import { reactive } from 'vue'
import { useRouter } from 'vue-router'
import Button from '../components/ui/Button.vue'
import Input from '../components/ui/Input.vue'
import { useAuthStore } from '../stores/useAuthStore'

const store = useAuthStore()
const router = useRouter()
const form = reactive({
  username: '',
  password: '',
})

const submit = async () => {
  const ok = await store.login(form)
  if (ok) {
    router.push('/')
  }
}
</script>
