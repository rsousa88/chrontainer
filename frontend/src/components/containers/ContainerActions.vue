<template>
  <div class="flex flex-wrap items-center gap-2">
    <Button variant="ghost" @click="notify('Restart')">Restart</Button>
    <Button variant="ghost" @click="notify('Stop')">Stop</Button>
    <Button variant="ghost" @click="notify('Start')">Start</Button>
    <Button variant="ghost" @click="notify('Update')">Update</Button>
  </div>
</template>

<script setup>
import Button from '../ui/Button.vue'
import { useToastStore } from '../../stores/useToastStore'

const toastStore = useToastStore()

const notify = (action) => {
  toastStore.push({ title: action, message: `${action} action triggered.` })
}
</script>
