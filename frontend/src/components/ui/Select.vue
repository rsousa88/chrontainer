<template>
  <label class="block space-y-2 text-sm">
    <span v-if="label" class="text-surface-300">{{ label }}</span>
    <select
      v-bind="$attrs"
      :value="modelValue"
      @change="$emit('update:modelValue', $event.target.value)"
      class="w-full rounded-xl border border-surface-700 bg-surface-800 px-3 py-2 text-sm text-surface-100 focus:border-brand-400 focus:outline-none"
    >
      <slot />
    </select>
    <span v-if="hint" class="text-xs text-surface-500">{{ hint }}</span>
  </label>
</template>

<script setup>
defineProps({
  modelValue: {
    type: [String, Number],
    default: '',
  },
  label: String,
  hint: String,
})

defineEmits(['update:modelValue'])
</script>
