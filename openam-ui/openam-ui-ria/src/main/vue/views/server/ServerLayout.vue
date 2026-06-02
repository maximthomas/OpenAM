<template>
  <div class="row">
    <div class="col-sm-3 col-md-2 sidebar">
      <div class="sidebar-header">
        <i class="fa fa-server"></i>
        <span>{{ serverName }}</span>
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

const serverName = computed(() => {
  const name = route.params.serverName;
  return Array.isArray(name) ? name[0] : (name ?? '');
});

const navItems = computed(() => [
  { route: 'editServerGeneral', icon: 'fa-cog', label: t('console.common.navigation.general'), to: { name: 'editServerGeneral', params: { serverName: serverName.value } } },
  { route: 'editServerSecurity', icon: 'fa-lock', label: t('console.common.navigation.security'), to: { name: 'editServerSecurity', params: { serverName: serverName.value } } },
  { route: 'editServerSession', icon: 'fa-ticket', label: t('console.common.navigation.session'), to: { name: 'editServerSession', params: { serverName: serverName.value } } },
  { route: 'editServerSdk', icon: 'fa-th', label: t('console.common.navigation.sdk'), to: { name: 'editServerSdk', params: { serverName: serverName.value } } },
  { route: 'editServerCts', icon: 'fa-database', label: t('console.common.navigation.cts'), to: { name: 'editServerCts', params: { serverName: serverName.value } } },
  { route: 'editServerUma', icon: 'fa-check-circle-o', label: t('console.common.navigation.uma'), to: { name: 'editServerUma', params: { serverName: serverName.value } } },
  { route: 'editServerAdvanced', icon: 'fa-cogs', label: t('console.common.navigation.advanced'), to: { name: 'editServerAdvanced', params: { serverName: serverName.value } } },
  { route: 'editServerDirectoryConfiguration', icon: 'fa-folder-open', label: t('console.common.navigation.directoryConfiguration'), to: { name: 'editServerDirectoryConfiguration', params: { serverName: serverName.value } } },
]);

function isActive(routeName: string): boolean {
  return route.name === routeName;
}
</script>
