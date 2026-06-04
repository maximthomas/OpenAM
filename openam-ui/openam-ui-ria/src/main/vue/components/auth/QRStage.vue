<template>
  <div class="qr-stage text-center">
    <div class="container">
      <form class="form login col-sm-6 col-sm-offset-3" autocomplete="off">
        <fieldset class="row" style="text-align: center;">
          <img v-if="qrImageUrl" :src="qrImageUrl" alt="QR Code" />
        </fieldset>
        <fieldset class="row">
          <p v-if="qrText" style="word-break: break-all">{{ qrText }}</p>
          <div class="panel panel-default">
            <div class="panel-body text-center">
              <h4 class="awaiting-response">
                <i class="fa fa-circle-o-notch fa-spin text-primary" />
                {{ $t('templates.user.LoginTemplate.waitingForResponse') }}
              </h4>
            </div>
          </div>
        </fieldset>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { AuthCallback } from '@/types/user';

const props = defineProps<{
  callbacks: AuthCallback[];
}>();

const qrImageUrl = computed(() => {
  const cb = props.callbacks[0];
  if (cb) {
    const url = cb.output?.find((o) => o.name === 'image');
    return typeof url?.value === 'string' ? url.value : '';
  }
  return '';
});

const qrText = computed(() => {
  const cb = props.callbacks[1];
  if (cb) {
    const text = cb.output?.find((o) => o.name === 'message');
    return typeof text?.value === 'string' ? text.value : '';
  }
  return '';
});
</script>
