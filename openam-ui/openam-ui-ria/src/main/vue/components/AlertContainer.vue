<template>
  <div class="alert-container">
    <div
      v-for="(message, index) in messages"
      :key="index"
      :class="['alert', `alert-${message.type}`, 'alert-dismissible']"
      role="alert"
    >
      <button type="button" class="close" @click="dismiss(message)">
        <span>&times;</span>
      </button>
      {{ t(message.key) }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';
import { useAlert } from '@/composables/useAlert';
import type { AlertMessage } from '@/composables/useAlert';

const { t } = useI18n();
const { messages, dismiss } = useAlert();
</script>

<style scoped>
.alert-container {
  position: fixed;
  top: 60px;
  left: 0;
  right: 0;
  z-index: 1050;
  padding: 0 15px;
  pointer-events: none;
}

.alert-container .alert {
  pointer-events: auto;
  margin: 5px auto;
  max-width: 600px;
}
</style>
