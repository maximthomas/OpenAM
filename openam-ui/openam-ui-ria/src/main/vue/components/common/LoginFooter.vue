<template>
  <div class="container">
    <p>
      <a :href="`mailto: ${footer.mailto}`">{{ footer.mailto }}</a>
      <template v-if="footer.phone">
        {{ t('templates.user.DefaultBaseTemplate.orPhone') }} {{ footer.phone }}.
      </template>
      <br />
      <span v-html="t('common.form.copyright')" />
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { config } from '@/services/config';

const { t } = useI18n();

const footer = computed(() => config.globalData.theme?.settings?.footer ?? { mailto: '' });
</script>
