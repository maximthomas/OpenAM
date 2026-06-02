<template>
  <div class="row">
    <div class="col-sm-3 col-md-2 sidebar">
      <div class="sidebar-header">
        <i class="fa fa-cloud"></i>
        <span>{{ realmName }}</span>
      </div>
      <ul class="nav nav-sidebar">
        <li v-for="item in navItems" :key="item.route" :class="{ active: isActive(item.route) }">
          <router-link :to="item.to">
            <i :class="['fa', item.icon]"></i>
            {{ item.label }}
          </router-link>
          <ul v-if="item.children" class="nav nav-sidebar nested">
            <li v-for="child in item.children" :key="child.route" :class="{ active: isActive(child.route) }">
              <router-link :to="child.to">
                <i :class="['fa', child.icon]"></i>
                {{ child.label }}
              </router-link>
            </li>
          </ul>
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
import { useRealm } from '@/composables/useRealm';

const { t } = useI18n();
const route = useRoute();
const { realmPath, decodedRealmPath } = useRealm();

const realmName = computed(() => {
  const parts = decodedRealmPath.value.split('/').filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : t('console.common.navigation.topLevelRealm');
});

function realmRoute(routeName: string) {
  return { name: routeName, params: { realmPath: realmPath.value } };
}

const navItems = computed(() => [
  {
    route: 'realmsDashboard',
    icon: 'fa-dashboard',
    label: t('console.common.navigation.dashboard'),
    to: realmRoute('realmsDashboard'),
  },
  {
    route: 'applications',
    icon: 'fa-list-alt',
    label: t('console.common.navigation.applications'),
    to: {},
    children: [
      { route: 'saml20', icon: 'fa-angle-right', label: t('console.common.navigation.saml20'), to: {} },
      { route: 'wsfed', icon: 'fa-angle-right', label: t('console.common.navigation.wsfed'), to: {} },
      { route: 'oauth20', icon: 'fa-angle-right', label: t('console.common.navigation.oauth20'), to: {} },
      { route: 'javaAgents', icon: 'fa-angle-right', label: t('console.common.navigation.javaAgents'), to: {} },
      { route: 'webAgents', icon: 'fa-angle-right', label: t('console.common.navigation.webAgents'), to: {} },
    ],
  },
  {
    route: 'authentication',
    icon: 'fa-user',
    label: t('console.common.navigation.authentication'),
    to: {},
    children: [
      { route: 'realmsAuthenticationSettings', icon: 'fa-angle-right', label: t('console.common.navigation.settings'), to: realmRoute('realmsAuthenticationSettings') },
      { route: 'realmsAuthenticationChains', icon: 'fa-angle-right', label: t('console.common.navigation.chains'), to: realmRoute('realmsAuthenticationChains') },
      { route: 'realmsAuthenticationModules', icon: 'fa-angle-right', label: t('console.common.navigation.modules'), to: realmRoute('realmsAuthenticationModules') },
    ],
  },
  {
    route: 'realmsServices',
    icon: 'fa-plug',
    label: t('console.common.navigation.services'),
    to: realmRoute('realmsServices'),
  },
  {
    route: 'realmsSessions',
    icon: 'fa-ticket',
    label: t('console.common.navigation.sessions'),
    to: realmRoute('realmsSessions'),
  },
  {
    route: 'authorization',
    icon: 'fa-key',
    label: t('console.common.navigation.authorization'),
    to: {},
    children: [
      { route: 'realmsPolicySets', icon: 'fa-angle-right', label: t('console.common.navigation.policySets'), to: realmRoute('realmsPolicySets') },
      { route: 'realmsResourceTypes', icon: 'fa-angle-right', label: t('console.common.navigation.resourceTypes'), to: realmRoute('realmsResourceTypes') },
    ],
  },
  {
    route: 'realmsScripts',
    icon: 'fa-code',
    label: t('console.common.navigation.scripts'),
    to: realmRoute('realmsScripts'),
  },
]);

function isActive(routeName: string): boolean {
  return route.name === routeName;
}
</script>
