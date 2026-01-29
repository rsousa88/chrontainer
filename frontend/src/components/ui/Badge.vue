<template>
  <span :class="['inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold', badgeClasses]">
    <slot />
  </span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  tone: {
    type: String,
    default: 'neutral',
  },
})

const badgeClasses = computed(() => {
  const map = {
    neutral: 'bg-surface-800 text-surface-200',
    success: 'bg-emerald-500/20 text-emerald-200',
    warning: 'bg-amber-400/20 text-amber-200',
    danger: 'bg-rose-500/20 text-rose-200',
    info: 'bg-brand-500/20 text-brand-200',
  }
  return map[props.tone] || map.neutral
})
</script>
