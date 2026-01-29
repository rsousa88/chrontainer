<template>
  <button
    :type="type"
    :class="[
      'inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition',
      variantClasses,
      fullWidth ? 'w-full' : '',
      disabled ? 'opacity-50 cursor-not-allowed' : 'hover:shadow-lg hover:shadow-brand-500/20'
    ]"
    :disabled="disabled"
  >
    <slot />
  </button>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  variant: {
    type: String,
    default: 'primary',
  },
  type: {
    type: String,
    default: 'button',
  },
  fullWidth: {
    type: Boolean,
    default: false,
  },
  disabled: {
    type: Boolean,
    default: false,
  },
})

const variantClasses = computed(() => {
  const map = {
    primary: 'bg-brand-500 text-white hover:bg-brand-400',
    secondary: 'bg-surface-800 text-surface-100 hover:bg-surface-700',
    ghost: 'border border-surface-700 text-surface-200 hover:border-brand-400 hover:text-brand-200',
    danger: 'bg-rose-500/80 text-white hover:bg-rose-500',
  }
  return map[props.variant] || map.primary
})
</script>
