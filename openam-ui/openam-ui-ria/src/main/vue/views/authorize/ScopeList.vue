<template>
  <div class="panel-group form-horizontal" aria-multiselectable="true">
    <template v-for="(item, index) in items" :key="index">
      <div v-if="item.values" class="panel panel-info">
        <div
          class="panel-heading clearfix am-panel-heading-hover clearfix"
          :aria-expanded="!!openPanels[index]"
          :aria-controls="`${idPrefix}${index}`"
          role="tab"
          tabindex="0"
          @click="togglePanel(index)"
          @keyup.enter="togglePanel(index)"
          @keyup.space.prevent="togglePanel(index)"
        >
          <span v-html="item.name" />
          <div class="pull-right"><i class="fa fa-angle-down" /></div>
        </div>
        <div
          :id="`${idPrefix}${index}`"
          class="panel-collapse"
          role="tabpanel"
          :aria-expanded="!!openPanels[index]"
          v-if="openPanels[index]"
        >
          <div class="panel-body">
            <template v-if="Array.isArray(item.values)">
              <small v-html="item.values.toString()" /><br />
            </template>
            <template v-else-if="typeof item.values === 'string'">
              <small v-html="item.values" /><br />
            </template>
            <template v-else>
              <div v-for="(val, key) in item.values" :key="key">
                <small><strong v-html="String(key) + ':'"></strong> <span v-html="String(val)" /></small><br />
              </div>
            </template>
          </div>
        </div>
      </div>
      <div v-else class="panel panel-default">
        <div class="panel-heading"><span v-html="item.name" /></div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue';
import type { AuthorizeScope } from '@/types/authorize';

defineProps<{
  items: AuthorizeScope[];
  idPrefix: string;
}>();

const openPanels = reactive<Record<number, boolean>>({});

function togglePanel(index: number): void {
  openPanels[index] = !openPanels[index];
}
</script>
