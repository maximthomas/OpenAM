<template>
  <footer class="footer">
    <div class="container">
      <p>
        <a :href="`mailto: ${footer.mailto}`">{{ footer.mailto }}</a>
        <template v-if="footer.phone">
          {{ t('templates.user.DefaultBaseTemplate.orPhone') }} {{ footer.phone }}.
        </template>
        <br />
        <span v-html="t('common.form.copyright')" />
        <template v-if="version">
          &mdash; v{{ version }}
        </template>
      </p>
    </div>
  </footer>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { useAuth } from '@/composables/useAuth';
import { config } from '@/services/config';

const { t } = useI18n();
const { hasRole } = useAuth();

const footer = computed(() => config.globalData.theme?.settings?.footer ?? { mailto: '' });
const version = computed(() => {
  if (hasRole('ui-realm-admin') || hasRole('ui-global-admin')) {
    return config.globalData.version ?? '';
  }
  return '';
});
</script>
