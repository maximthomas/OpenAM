<template>
  <div id="wrapper">
    <AppHeader />
    <AlertContainer />
    <div class="container-fluid">
      <router-view />
    </div>
    <AppFooter />
  </div>
</template>

<script setup lang="ts">
import AppHeader from '@/components/AppHeader.vue';
import AppFooter from '@/components/AppFooter.vue';
import AlertContainer from '@/components/AlertContainer.vue';
</script>
