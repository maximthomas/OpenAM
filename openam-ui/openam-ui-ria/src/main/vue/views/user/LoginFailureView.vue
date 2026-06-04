<template>
  <ReturnToLoginBase :title="title" :params="params" />
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';
import ReturnToLoginBase from '@/components/auth/ReturnToLoginBase.vue';
import { useLogin } from '@/composables/useLogin';

const { t } = useI18n();
const route = useRoute();
const login = useLogin();

const title = ref(t('openam.authentication.unavailable') || 'Login Unavailable');
const params = ref('');

onMounted(() => {
  login.removeAuthIdCookie();
  const paramsObj = route.query;
  const paramStr = Object.entries(paramsObj)
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
  params.value = paramStr ? `&${paramStr}` : '';
});
</script>
