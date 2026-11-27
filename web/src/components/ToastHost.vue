<script setup lang="ts">
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-vue-next'
import { dismissToast, toasts } from '../toast'
</script>

<template>
  <div class="toast-stack" aria-live="polite">
    <TransitionGroup name="toast">
      <div v-for="item in toasts" :key="item.id" class="toast-item" :class="`toast-${item.kind}`">
        <CheckCircle2 v-if="item.kind === 'success'" :size="16" class="toast-ico-ok" />
        <AlertCircle v-else-if="item.kind === 'error'" :size="16" class="toast-ico-err" />
        <Info v-else :size="16" class="toast-ico-info" />
        <span class="toast-msg">{{ item.message }}</span>
        <button class="toast-close" type="button" @click="dismissToast(item.id)">
          <X :size="14" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>
