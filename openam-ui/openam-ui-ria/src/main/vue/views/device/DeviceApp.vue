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
      <DeviceError
        v-if="pageData.errorCode"
        :error-code="pageData.errorCode"
      />
      <DeviceDone v-else-if="pageData.done" />
      <DeviceForm v-else />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { DevicePageData } from '@/types/device';
import LoginHeader from '@/components/common/LoginHeader.vue';
import DeviceForm from '@/views/device/DeviceForm.vue';
import DeviceDone from '@/views/device/DeviceDone.vue';
import DeviceError from '@/views/device/DeviceError.vue';
import { config } from '@/services/config';

const props = defineProps<{
  pageData: DevicePageData;
}>();

config.globalData.realm = props.pageData.realm;

const loginLogoHeight = computed(
  () => config.globalData.theme?.settings?.loginLogo?.height ?? '',
);
</script>
