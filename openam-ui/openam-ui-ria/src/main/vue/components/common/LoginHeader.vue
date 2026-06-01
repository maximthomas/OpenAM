<template>
  <img
    v-if="logo"
    class="main-logo"
    :src="logo.src"
    :width="logo.width"
    :height="logo.height"
    :alt="logo.alt"
  />
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { config } from '@/services/config';

const logo = computed(() => config.globalData.theme?.settings?.loginLogo ?? null);
</script>
