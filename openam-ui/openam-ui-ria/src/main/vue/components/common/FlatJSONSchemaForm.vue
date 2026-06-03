<template>
  <JSONSchemaForm
    ref="editorRef"
    :schema="processedSchema"
    :values="values"
    :display-title="false"
  />
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { intersection } from 'lodash';
import { JSONSchema } from '@/services/jsonSchema/JSONSchema';
import { JSONValues } from '@/services/jsonSchema/JSONValues';
import JSONSchemaForm from './JSONSchemaForm.vue';

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

const editorRef = ref<InstanceType<typeof JSONSchemaForm>>();

const processedSchema = computed(() => {
  if (!props.showOnlyRequiredAndEmpty) {
    return props.schema;
  }

  const requiredSchemaKeys = props.schema.getRequiredPropertyKeys();
  const emptyValueKeys = props.values.getEmptyValueKeys();
  const requiredAndEmptyKeys = intersection(requiredSchemaKeys, emptyValueKeys);

  return props.schema.removeUnrequiredProperties().addDefaultProperties(requiredAndEmptyKeys);
});

onMounted(() => {
  setTimeout(() => {
    emit('rendered');
  }, 0);
});

function isValid(): boolean {
  return editorRef.value?.isValid() ?? true;
}

function getData(): Record<string, unknown> {
  return editorRef.value?.getData() || {};
}

function setData(data: Record<string, unknown>): void {
  editorRef.value?.setData(data);
}

defineExpose({
  isValid,
  getData,
  setData,
});
</script>
