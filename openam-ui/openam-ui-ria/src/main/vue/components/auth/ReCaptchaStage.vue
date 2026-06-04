<template>
  <div class="recaptcha-stage">
    <div class="container">
      <div class="form col-sm-6 col-sm-offset-3">
        <div id="recaptcha-container" class="g-recaptcha" :data-sitekey="siteKey" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue';
import type { AuthCallback } from '@/types/user';

const props = defineProps<{
  callbacks: AuthCallback[];
}>();

const emit = defineEmits<{
  token: [value: string];
}>();

const siteKey = computed(() => {
  const cb = props.callbacks.find((cb) => cb.type === 'HiddenValueCallback');
  if (cb) {
    const siteKey = cb.output?.find((o) => o.name === 'id');
    return typeof siteKey?.value === 'string' ? siteKey.value : '';
  }
  return '';
});

let captchaInterval: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  const checkGrecaptcha = () => {
    if (typeof window !== 'undefined' && (window as unknown as { grecaptcha?: { getResponse: () => string } }).grecaptcha) {
      captchaInterval = setInterval(() => {
        const response = (window as unknown as { grecaptcha: { getResponse: () => string } }).grecaptcha.getResponse();
        if (response) {
          emit('token', response);
        }
      }, 1000);
    } else {
      setTimeout(checkGrecaptcha, 200);
    }
  };
  checkGrecaptcha();
});

onUnmounted(() => {
  if (captchaInterval) {
    clearInterval(captchaInterval);
  }
});
</script>
