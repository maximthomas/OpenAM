<template>
  <div class="container">
    <div class="jumbotron text-center">
      <h1>{{ t('common.form.thankYou') }}</h1>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';

const { t } = useI18n();
</script>
