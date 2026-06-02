<template>
  <div class="text-center">
    <h1>404</h1>
    <p>{{ t('console.common.errors.pageNotFound') }}</p>
    <router-link to="/" class="btn btn-primary">
      {{ t('console.common.navigation.home') }}
    </router-link>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';

const { t } = useI18n();
</script>
