<template>
  <ReturnToLoginBase :title="title" :params="params" />
</template>

<script setup lang="ts">
import ReturnToLoginBase from '@/components/auth/ReturnToLoginBase.vue';

const title = 'Logged Out';
const params = '';
</script>
