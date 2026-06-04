<template>
  <div class="webauthn-stage text-center">
    <div class="panel panel-default">
      <div class="panel-body">
        <i class="fa fa-spinner fa-spin fa-3x text-primary" />
        <h4>{{ $t('templates.user.LoginTemplate.webauthnAuthentication') || 'Authenticating with WebAuthn...' }}</h4>
        <p class="text-muted">{{ message }}</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { AuthCallback } from '@/types/user';

const props = defineProps<{
  callbacks: AuthCallback[];
}>();

const message = computed(() => {
  const textCb = props.callbacks.find((cb) => cb.type === 'TextOutputCallback');
  if (textCb) {
    const msg = textCb.output?.find((o) => o.name === 'message');
    return typeof msg?.value === 'string' ? msg.value : '';
  }
  return '';
});
</script>
