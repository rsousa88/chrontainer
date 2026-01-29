<template>
  <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center">
    <div class="absolute inset-0 bg-black/70" @click="onClose" />
    <div class="relative z-10 w-full max-w-lg rounded-2xl border border-surface-800 bg-surface-900 p-6">
      <div class="flex items-start justify-between">
        <div>
          <h3 class="text-lg font-semibold text-surface-50">{{ title }}</h3>
          <p v-if="subtitle" class="text-sm text-surface-400">{{ subtitle }}</p>
        </div>
        <button class="text-surface-400 hover:text-surface-200" @click="onClose">✕</button>
      </div>
      <div class="mt-4 text-sm text-surface-300">
        <slot />
      </div>
      <div class="mt-6 flex justify-end gap-3">
        <slot name="actions" />
      </div>
    </div>
  </div>
</template>

<script setup>
const props = defineProps({
  open: {
    type: Boolean,
    default: false,
  },
  title: {
    type: String,
    default: 'Modal Title',
  },
  subtitle: String,
})

const emit = defineEmits(['close'])

const onClose = () => emit('close')
</script>
