<template>
  <div class="overflow-hidden rounded-2xl border border-surface-800">
    <table class="w-full border-collapse text-left text-sm">
      <thead class="bg-surface-800 text-surface-300">
        <tr>
          <slot name="head" />
        </tr>
      </thead>
      <tbody class="divide-y divide-surface-800 bg-surface-900/60 text-surface-100">
        <slot />
      </tbody>
    </table>
  </div>
</template>
