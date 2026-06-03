<template>
  <div>
    <div v-for="pair in processedPairs" :key="pair.key">
      <TogglableJSONSchemaForm
        v-if="pair.schema.hasEnableProperty()"
        :ref="(el: any) => setEditorRef(pair.key, el)"
        :schema="pair.schema"
        :values="pair.values"
      />
      <JSONSchemaForm
        v-else
        :ref="(el: any) => setEditorRef(pair.key, el)"
        :schema="pair.schema"
        :values="pair.values"
        :display-title="false"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { map, reduce } from 'lodash';
import { JSONSchema } from '@/services/jsonSchema/JSONSchema';
import { JSONValues } from '@/services/jsonSchema/JSONValues';
import type { SchemaValuePair } from '@/services/jsonSchema/index';
import {
  setDefaultPropertiesToRequiredAndEmpty,
  showEnablePropertyIfAllPropertiesHidden,
  emptyProperties,
} from '@/services/jsonSchema/index';
import JSONSchemaForm from './JSONSchemaForm.vue';
import TogglableJSONSchemaForm from './TogglableJSONSchemaForm.vue';

const props = withDefaults(
  defineProps<{
    schema: JSONSchema;
    values: JSONValues;
    showOnlyRequiredAndEmpty?: boolean;
  }>(),
  {
    showOnlyRequiredAndEmpty: false,
  }
);

const emit = defineEmits<{
  rendered: [];
}>();

interface EditorRef {
  getData(): Record<string, unknown>;
  isValid?(): boolean;
}

const editorRefs = ref<Record<string, EditorRef | null>>({});

function setEditorRef(key: string, el: unknown): void {
  editorRefs.value[key] = el as EditorRef | null;
}

const processedPairs = computed<SchemaValuePair[]>(() => {
  const schemas = props.schema.getPropertiesAsSchemas();
  const values = props.values.raw as Record<string, unknown>;
  const orderedKeys = props.schema.getKeys(true);

  let pairs: SchemaValuePair[] = map(orderedKeys, (key: string) => ({
    key,
    schema: schemas[key],
    values: new JSONValues((values[key] as Record<string, unknown>) || {}),
  }));

  if (props.showOnlyRequiredAndEmpty) {
    pairs = pairs
      .map(setDefaultPropertiesToRequiredAndEmpty)
      .map(showEnablePropertyIfAllPropertiesHidden)
      .filter((pair: SchemaValuePair) => !emptyProperties(pair));
  }

  return pairs;
});

onMounted(() => {
  setTimeout(() => {
    emit('rendered');
  }, 0);
});

function getData(): Record<string, unknown> {
  const values = map(processedPairs.value, (pair: SchemaValuePair) => {
    const ref = editorRefs.value[pair.key];
    if (!ref) {
      return {};
    }
    const data = ref.getData();
    if (pair.key) {
      return { [pair.key]: data };
    }
    return data;
  });

  return reduce(values, (acc: Record<string, unknown>, val: Record<string, unknown>) => ({ ...acc, ...val }), {});
}

defineExpose({
  getData,
});
</script>
