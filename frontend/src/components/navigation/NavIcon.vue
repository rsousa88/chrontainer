<template>
  <span class="flex h-10 w-10 items-center justify-center rounded-xl border border-surface-700 bg-surface-800 text-brand-200">
    <component :is="iconComponent" class="h-5 w-5" />
  </span>
</template>

<script setup>
import { computed } from 'vue'
import {
  HomeIcon,
  CubeIcon,
  DocumentTextIcon,
  ChartBarIcon,
  Cog6ToothIcon,
  CalendarDaysIcon,
  ServerStackIcon,
} from '@heroicons/vue/24/outline'

const props = defineProps({
  name: {
    type: String,
    required: true,
  },
})

const iconComponent = computed(() => {
  const map = {
    home: HomeIcon,
    cube: CubeIcon,
    document: DocumentTextIcon,
    chart: ChartBarIcon,
    cog: Cog6ToothIcon,
    calendar: CalendarDaysIcon,
    server: ServerStackIcon,
  }
  return map[props.name] || HomeIcon
})
</script>
