<template>
  <div class="placeholder-view">
    <h2>{{ title }}</h2>
    <div class="alert alert-info">
      <i class="fa fa-info-circle"></i>
      Not yet migrated to Vue.
      <template v-if="view">
        <br />
        <small>Backbone view: <code>{{ view }}</code></small>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const title = 'Edit Policy Set';
const view = 'openam/ui/admin/views/realms/authorization/policySets/EditPolicySetView';
</script>
