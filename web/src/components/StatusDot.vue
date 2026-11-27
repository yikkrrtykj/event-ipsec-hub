<script setup lang="ts">
defineProps<{
  state: 'ok' | 'warn' | 'critical' | 'unknown'
  label?: string
  pulse?: boolean
}>()
</script>

<template>
  <span class="status-inline">
    <span class="status-dot" :class="[`dot-${state}`, { 'dot-pulse': pulse }]"></span>
    <span v-if="label" class="status-text" :class="`st-text-${state}`">{{ label }}</span>
  </span>
</template>
