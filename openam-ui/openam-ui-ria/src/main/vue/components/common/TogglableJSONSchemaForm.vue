<template>
  <div class="jsoneditor-block">
    <div class="form-group">
      <div class="row">
        <div class="col-sm-12">
          <div
            :class="['block-header', { 'block-header-inactive': !isEnabled }]"
          >
            <label class="control-label">
              <input
                type="checkbox"
                :checked="isEnabled"
                @change="onToggle"
              />
              {{ headerTitle }}
            </label>
          </div>
        </div>
      </div>
    </div>
    <div v-show="isEnabled && !schema.isEmpty()">
      <JSONSchemaForm
        ref="innerEditor"
        :schema="schema"
        :values="values"
        :display-title="false"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { JSONSchema } from '@/services/jsonSchema/JSONSchema';
import { JSONValues } from '@/services/jsonSchema/JSONValues';
import JSONSchemaForm from './JSONSchemaForm.vue';

const props = defineProps<{
  schema: JSONSchema;
  values: JSONValues;
}>();

const innerEditor = ref<InstanceType<typeof JSONSchemaForm>>();

const enablePropertyKey = computed(() => props.schema.getEnableKey());
const isEnabled = ref(false);
const headerTitle = computed(() => props.schema.raw.title || '');

const innerSchema = computed(() => {
  const key = enablePropertyKey.value;
  return key ? props.schema.omit(key) : props.schema;
});

const innerValues = computed(() => {
  const key = enablePropertyKey.value;
  return key ? props.values.omit(key) : props.values;
});

onMounted(() => {
  const key = enablePropertyKey.value;
  if (key) {
    isEnabled.value = Boolean(props.values.raw[key]);
  }
});

function onToggle(event: Event): void {
  const target = event.target as HTMLInputElement;
  isEnabled.value = target.checked;
}

function getData(): Record<string, unknown> {
  const data = innerEditor.value?.getData() || {};
  if (enablePropertyKey.value) {
    return {
      ...data,
      [enablePropertyKey.value]: isEnabled.value,
    };
  }
  return data;
}

defineExpose({
  getData,
});
</script>
