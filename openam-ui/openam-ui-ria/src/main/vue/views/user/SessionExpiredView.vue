<template>
  <ReturnToLoginBase :title="title" :params="params" />
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import ReturnToLoginBase from '@/components/auth/ReturnToLoginBase.vue';
import { config } from '@/services/config';

const { t } = useI18n();
const title = ref(t('templates.user.SessionExpiredTemplate.sessionExpired') || 'Session Expired');
const params = ref('');

onMounted(() => {
  const fullLoginURL = config.globalData.auth.fullLoginURL;
  if (fullLoginURL) {
    const queryString = fullLoginURL.substring(fullLoginURL.indexOf('?') + 1);
    if (queryString) {
      params.value = `&${queryString}`;
    }
  }
  delete config.globalData.auth.fullLoginURL;
});
</script>
