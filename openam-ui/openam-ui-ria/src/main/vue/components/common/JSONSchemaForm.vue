<template>
  <div ref="editorEl" class="jsoneditor-block"></div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch } from 'vue';
import { JSONSchema } from '@/services/jsonSchema/JSONSchema';
import { JSONValues } from '@/services/jsonSchema/JSONValues';
import { getTheme } from '@/services/jsonSchema/JSONEditorTheme';
import '@/vendor/jsoneditor-0.7.23-custom';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const JSONEditor: any;

const GRID_COLUMN_WIDTH_1 = 6;
const GRID_COLUMN_WIDTH_2 = 4;

const props = withDefaults(
  defineProps<{
    schema: JSONSchema;
    values: JSONValues;
    displayTitle?: boolean;
  }>(),
  {
    displayTitle: true,
  }
);

const editorEl = ref<HTMLDivElement>();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let editorInstance: any = null;

function createEditor(): void {
  if (!editorEl.value || !props.schema || !props.values) {
    return;
  }

  editorEl.value.innerHTML = '';

  JSONEditor.plugins.selectize.enable = true;
  JSONEditor.defaults.themes.openam = getTheme(GRID_COLUMN_WIDTH_1, GRID_COLUMN_WIDTH_2);

  const hasInheritance = props.schema.hasInheritance();
  let actualSchema: JSONSchema;
  let actualValues: JSONValues;

  if (hasInheritance) {
    actualSchema = props.schema.toFlatWithInheritanceMeta(props.values);
    actualValues = props.values.removeInheritance();
  } else {
    actualSchema = props.schema;
    actualValues = props.values;
  }

  editorInstance = new JSONEditor(editorEl.value, {
    disable_collapse: true,
    disable_edit_json: true,
    disable_properties: true,
    iconlib: 'fontawesome4',
    schema: actualSchema.raw,
    theme: 'openam',
  });

  editorInstance.setValue(actualValues.raw);

  if (!props.displayTitle) {
    const headers = editorEl.value.querySelectorAll('[data-header]');
    headers.forEach((el: Element) => {
      const parent = el.parentElement;
      if (parent) {
        parent.style.display = 'none';
      }
    });
  }

  const passwordInputs = editorEl.value.querySelectorAll('input[type="password"]');
  passwordInputs.forEach((input: Element) => {
    (input as HTMLInputElement).setAttribute('placeholder', 'Password unchanged if left empty');
  });
}

onMounted(() => {
  createEditor();
});

onBeforeUnmount(() => {
  if (editorInstance) {
    editorInstance.destroy?.();
    editorInstance = null;
  }
});

watch(
  () => [props.schema, props.values],
  () => {
    createEditor();
  }
);

function isValid(): boolean {
  if (!editorInstance) {
    return true;
  }
  return editorInstance.validate().length === 0;
}

function getData(): Record<string, unknown> {
  if (!editorInstance) {
    return {};
  }

  const passwordKeys = props.schema.getPasswordKeys();
  let values = new JSONValues(editorInstance.getValue());

  if (props.schema.hasDefaultProperties()) {
    values = values.pick(props.schema.raw.defaultProperties as string[]);
  }

  let valuesWithoutEmptyPasswords = values.omit((value: unknown, key: string) => {
    if (passwordKeys.indexOf(key) !== -1 && !value) {
      return true;
    }
    return false;
  });

  if (props.schema.hasInheritance()) {
    valuesWithoutEmptyPasswords = valuesWithoutEmptyPasswords.addInheritance(
      props.values.raw as Record<string, { inherited: boolean }>
    );
  }

  return valuesWithoutEmptyPasswords.raw;
}

function setData(data: Record<string, unknown>): void {
  if (!editorInstance) {
    return;
  }
  const currentValues = new JSONValues(editorInstance.getValue());
  const extended = currentValues.extend(data);
  editorInstance.setValue(extended.raw);
}

defineExpose({
  isValid,
  getData,
  setData,
});
</script>
