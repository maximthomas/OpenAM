<template>
  <nav class="navbar navbar-default">
    <div class="container-fluid">
      <div class="navbar-header">
        <button
          type="button"
          class="navbar-toggle collapsed"
          data-toggle="collapse"
          data-target="#navbar-collapse"
        >
          <span class="sr-only">Toggle navigation</span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
        </button>
        <router-link class="navbar-brand" to="/">
          <img v-if="logo" :src="logo.src" :alt="logo.alt" :height="logo.height" :width="logo.width" />
          <span v-else>OpenAM</span>
        </router-link>
      </div>

      <div id="navbar-collapse" class="collapse navbar-collapse">
        <ul v-if="isAuthenticated" class="nav navbar-nav">
          <li v-if="isAdmin" :class="{ active: isAdminNav }">
            <router-link :to="{ name: 'realms' }">
              <i class="fa fa-cloud"></i>
              {{ t('console.common.navigation.realms') }}
            </router-link>
          </li>
          <li :class="{ active: isUserNav }">
            <router-link :to="{ name: 'profile' }">
              <i class="fa fa-user"></i>
              {{ t('console.common.navigation.profile') }}
            </router-link>
          </li>
        </ul>

        <ul v-if="isAuthenticated" class="nav navbar-nav navbar-right">
          <li class="dropdown">
            <a
              href="#"
              class="dropdown-toggle"
              data-toggle="dropdown"
              role="button"
            >
              {{ loggedUser?.username }}
              <span class="caret"></span>
            </a>
            <ul class="dropdown-menu">
              <li>
                <a href="#" @click.prevent="handleLogout">
                  <i class="fa fa-sign-out"></i>
                  {{ t('console.common.navigation.logout') }}
                </a>
              </li>
            </ul>
          </li>
          <li>
            <a href="https://docs.openam.org" target="_blank" rel="noopener">
              <i class="fa fa-question-circle"></i>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';
import { useAuth } from '@/composables/useAuth';
import { logout } from '@/services/logout';
import { config } from '@/services/config';

const { t } = useI18n();
const route = useRoute();
const { loggedUser, isAuthenticated, hasRole } = useAuth();

const isAdmin = computed(() => hasRole('ui-realm-admin') || hasRole('ui-global-admin'));

const isAdminNav = computed(() => route.meta.navGroup === 'admin');
const isUserNav = computed(() => route.meta.navGroup === 'user' || !isAdminNav.value);

const logo = computed(() => config.globalData.theme?.settings?.logo ?? null);

function handleLogout(): void {
  logout();
}
</script>
