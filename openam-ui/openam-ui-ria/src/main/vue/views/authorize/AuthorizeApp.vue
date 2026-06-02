<template>
  <div id="login-base">
    <div id="loginBaseLogo" class="main-logo-holder">
      <div
        v-if="loginLogoHeight"
        :style="{ height: loginLogoHeight }"
      />
      <LoginHeader />
    </div>
    <div id="content">
      <div class="container">
        <ErrorDisplay v-if="pageData.error" :error="pageData.error" />
        <AuthorizeForm v-else :page-data="pageData" />
      </div>
    </div>
    <div id="footer">
      <LoginFooter />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { AuthorizePageData } from '@/types/authorize';
import LoginHeader from '@/components/common/LoginHeader.vue';
import LoginFooter from '@/components/common/LoginFooter.vue';
import ErrorDisplay from '@/views/authorize/ErrorDisplay.vue';
import AuthorizeForm from '@/views/authorize/AuthorizeForm.vue';
import { config } from '@/services/config';

const props = defineProps<{
  pageData: AuthorizePageData;
}>();

config.globalData.realm = props.pageData.realm;

const loginLogoHeight = computed(
  () => config.globalData.theme?.settings?.loginLogo?.height ?? '',
);
</script>
