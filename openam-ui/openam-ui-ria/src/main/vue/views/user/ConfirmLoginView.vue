<template>
  <ReturnToLoginBase
    :title="title"
    :linkTitle="linkTitle"
    :params="params"
  />
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute, useRouter } from 'vue-router';
import ReturnToLoginBase from '@/components/auth/ReturnToLoginBase.vue';
import { useAuth } from '@/composables/useAuth';
import { logout } from '@/services/logout';

const { t } = useI18n();
const route = useRoute();
const router = useRouter();
const auth = useAuth();

const title = ref('');
const linkTitle = ref('');
const params = ref('');

onMounted(async () => {
  const realmChanged = route.query.realmChanged === 'true' || route.params.realmChanged === 'true';

  if (realmChanged) {
    await logout();
    title.value = t('common.user.loggedOutOfPreviousSite') || 'Logged out of previous site';
    linkTitle.value = t('common.user.logInToNewSite') || 'Log in to new site';
    params.value = '';
  } else {
    router.replace({ name: 'default' });
  }
});
</script>
