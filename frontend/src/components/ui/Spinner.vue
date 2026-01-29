<template>
  <div class="flex items-center gap-2 text-xs text-surface-400">
    <span class="h-4 w-4 animate-spin rounded-full border-2 border-surface-600 border-t-brand-400" />
    <span>{{ label }}</span>
  </div>
</template>

<script setup>
defineProps({
  label: {
    type: String,
    default: 'Loading',
  },
})
</script>
