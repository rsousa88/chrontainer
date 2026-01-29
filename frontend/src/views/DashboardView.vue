<template>
  <section class="space-y-6">
    <div class="flex flex-col gap-2">
      <p class="text-xs uppercase tracking-[0.3em] text-surface-500">Dashboard</p>
      <h2 class="text-2xl font-semibold text-surface-50">Containers Overview</h2>
      <p class="text-sm text-surface-400">Live container inventory and quick actions.</p>
    </div>
    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      <div class="rounded-2xl border border-surface-800 bg-surface-900/60 p-5">
        <p class="text-xs uppercase tracking-widest text-surface-500">Active</p>
        <p class="mt-3 text-3xl font-semibold text-brand-200">12</p>
        <p class="text-xs text-surface-500">Running containers</p>
      </div>
      <div class="rounded-2xl border border-surface-800 bg-surface-900/60 p-5">
        <p class="text-xs uppercase tracking-widest text-surface-500">Paused</p>
        <p class="mt-3 text-3xl font-semibold text-surface-100">0</p>
        <p class="text-xs text-surface-500">Temporarily halted</p>
      </div>
      <div class="rounded-2xl border border-surface-800 bg-surface-900/60 p-5">
        <p class="text-xs uppercase tracking-widest text-surface-500">Updates</p>
        <p class="mt-3 text-3xl font-semibold text-brand-300">2</p>
        <p class="text-xs text-surface-500">Available updates</p>
      </div>
    </div>
  </section>
</template>
