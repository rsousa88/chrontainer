<template>
  <div class="rounded-2xl border border-surface-800 bg-surface-900/70 p-5">
    <div v-if="title || subtitle" class="mb-4">
      <p v-if="eyebrow" class="text-xs uppercase tracking-[0.3em] text-surface-500">{{ eyebrow }}</p>
      <h3 v-if="title" class="text-lg font-semibold text-surface-50">{{ title }}</h3>
      <p v-if="subtitle" class="text-sm text-surface-400">{{ subtitle }}</p>
    </div>
    <slot />
  </div>
</template>

<script setup>
const props = defineProps({
  title: String,
  subtitle: String,
  eyebrow: String,
})
</script>
