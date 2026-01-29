<template>
  <div class="flex min-h-screen items-center justify-center bg-surface-950 px-6">
    <div class="w-full max-w-md rounded-2xl border border-surface-800 bg-surface-900/80 p-8">
      <div class="mb-6 text-center">
        <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Chrontainer</p>
        <h2 class="text-2xl font-semibold text-surface-50">Sign in</h2>
        <p class="text-sm text-surface-400">Welcome back to your container hub.</p>
      </div>
      <div class="space-y-4">
        <Input label="Username" placeholder="admin" />
        <Input label="Password" type="password" placeholder="••••••••" />
      </div>
      <div class="mt-6">
        <Button variant="primary" full-width>Login</Button>
      </div>
    </div>
  </div>
</template>

<script setup>
import Button from '../components/ui/Button.vue'
import Input from '../components/ui/Input.vue'
</script>
