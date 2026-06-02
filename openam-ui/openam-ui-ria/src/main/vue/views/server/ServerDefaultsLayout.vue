<template>
  <div class="row">
    <div class="col-sm-3 col-md-2 sidebar">
      <div class="sidebar-header">
        <i class="fa fa-server"></i>
        <span>{{ t('console.common.navigation.serverDefaults') }}</span>
      </div>
      <ul class="nav nav-sidebar">
        <li v-for="item in navItems" :key="item.route" :class="{ active: isActive(item.route) }">
          <router-link :to="item.to">
            <i :class="['fa', item.icon]"></i>
            {{ item.label }}
          </router-link>
        </li>
      </ul>
    </div>
    <div class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2 main">
      <router-view />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';

const { t } = useI18n();
const route = useRoute();

const navItems = computed(() => [
  { route: 'editServerDefaultsGeneral', icon: 'fa-cog', label: t('console.common.navigation.general'), to: { name: 'editServerDefaultsGeneral' } },
  { route: 'editServerDefaultsSecurity', icon: 'fa-lock', label: t('console.common.navigation.security'), to: { name: 'editServerDefaultsSecurity' } },
  { route: 'editServerDefaultsSession', icon: 'fa-ticket', label: t('console.common.navigation.session'), to: { name: 'editServerDefaultsSession' } },
  { route: 'editServerDefaultsSdk', icon: 'fa-th', label: t('console.common.navigation.sdk'), to: { name: 'editServerDefaultsSdk' } },
  { route: 'editServerDefaultsCts', icon: 'fa-database', label: t('console.common.navigation.cts'), to: { name: 'editServerDefaultsCts' } },
  { route: 'editServerDefaultsUma', icon: 'fa-check-circle-o', label: t('console.common.navigation.uma'), to: { name: 'editServerDefaultsUma' } },
  { route: 'editServerDefaultsAdvanced', icon: 'fa-cogs', label: t('console.common.navigation.advanced'), to: { name: 'editServerDefaultsAdvanced' } },
]);

function isActive(routeName: string): boolean {
  return route.name === routeName;
}
</script>
