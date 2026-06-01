<template>
  <div class="container">
    <div class="alert alert-warning col-md-6 col-md-offset-3" role="alert">
      <strong>{{ t(errorCode) }}</strong>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';

defineProps<{
  errorCode: string;
}>();

const { t } = useI18n();
</script>
