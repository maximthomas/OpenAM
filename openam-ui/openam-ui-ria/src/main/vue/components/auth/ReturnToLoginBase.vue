<template>
  <div class="container text-center">
    <LoginHeader />
    <div class="page-header">
      <h1>{{ title }}</h1>
    </div>
    <p>
      <a
        :href="loginHref"
        @click.prevent="returnToLogin"
      >
        {{ linkTitle || $t('common.user.returnToLoginPage') }}
      </a>
    </p>
    <slot />
    <LoginFooter />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import LoginHeader from '@/components/common/LoginHeader.vue';
import LoginFooter from '@/components/common/LoginFooter.vue';

const props = defineProps<{
  title: string;
  linkTitle?: string;
  params?: string;
}>();

const loginHref = computed(() => {
  const base = '#/login';
  const params = props.params ? props.params : '';
  return `${base}${params}`;
});

function returnToLogin(): void {
  window.location.replace(loginHref.value);
}
</script>
