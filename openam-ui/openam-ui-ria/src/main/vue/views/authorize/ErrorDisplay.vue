<template>
  <div class="alert alert-warning col-md-6 col-md-offset-3" role="alert">
    <strong>
      <a v-if="error.uri" :href="error.uri"><span v-html="error.message" /></a>
      <span v-else v-html="error.message" />
    </strong>
    <template v-if="error.description">
      <span v-html="error.description" />
    </template>
  </div>
</template>

<script setup lang="ts">
import type { AuthorizeError } from '@/types/authorize';

defineProps<{
  error: AuthorizeError;
}>();
</script>
