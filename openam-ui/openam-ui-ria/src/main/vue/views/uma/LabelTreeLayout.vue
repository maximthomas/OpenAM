<template>
  <div class="row">
    <div class="col-sm-3 col-md-2 sidebar">
      <div class="sidebar-header">
        <i class="fa fa-tags"></i>
        <span>{{ t('uma.resources.title') }}</span>
      </div>
      <ul class="nav nav-sidebar">
        <li :class="{ active: isActive('umaResourcesMyResources') }">
          <router-link :to="{ name: 'umaResourcesMyResources' }">
            <i class="fa fa-folder"></i>
            {{ t('uma.resources.myresources.title') }}
          </router-link>
        </li>
        <li :class="{ active: isActive('umaResourcesSharedWithMe') }">
          <router-link :to="{ name: 'umaResourcesSharedWithMe' }">
            <i class="fa fa-folder"></i>
            {{ t('uma.resources.sharedWithMe.title') }}
          </router-link>
        </li>
        <li :class="{ active: isActive('umaResourcesStarred') }">
          <router-link :to="{ name: 'umaResourcesStarred' }">
            <i class="fa fa-star"></i>
            {{ t('uma.resources.starred.title') }}
          </router-link>
        </li>
        <li class="nav-header">
          <i class="fa fa-tags"></i>
          {{ t('uma.resources.myLabels.title') }}
        </li>
      </ul>
    </div>
    <div class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2 main">
      <router-view />
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';

const { t } = useI18n();
const route = useRoute();

function isActive(routeName: string): boolean {
  return route.name === routeName;
}
</script>
