<template>
  <div>
    <table class="table table-bordered">
      <thead>
        <tr>
          <th v-for="col in columns" :key="col">{{ col }}</th>
          <th class="text-right">{{ t('common.form.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <InlineEditRow
          v-for="(row, index) in rows"
          :key="getRowKey(row, index)"
          :row="row"
          :columns="columns"
          :row-schema="rowSchema"
          :editing="activeRowIndex === index"
          @edit="activeRowIndex = index"
          @save="handleSave(index, $event)"
          @cancel="activeRowIndex = -1"
          @delete="handleDelete(index)"
        />
        <InlineEditRow
          :row="newRow"
          :columns="columns"
          :row-schema="rowSchema"
          editing
          @save="handleAdd"
          @cancel="showNewRow = false"
        />
      </tbody>
    </table>
    <button
      v-if="!showNewRow"
      type="button"
      class="btn btn-default btn-sm"
      @click="showNewRow = true"
    >
      <i class="fa fa-plus"></i> {{ t('common.form.add') }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import InlineEditRow from './InlineEditRow.vue';

const { t } = useI18n();

interface RowSchemaProperty {
  type?: string;
  enum?: string[];
  required?: boolean;
}

const props = withDefaults(
  defineProps<{
    rows: Record<string, unknown>[];
    columns: string[];
    rowSchema?: Record<string, RowSchemaProperty>;
    rowKey?: string;
  }>(),
  {
    rowSchema: () => ({
      key: { type: 'string', required: true },
      value: { type: 'string' },
    }),
    rowKey: 'key',
  }
);

const emit = defineEmits<{
  save: [index: number, data: Record<string, unknown>];
  add: [data: Record<string, unknown>];
  delete: [index: number];
}>();

const activeRowIndex = ref(-1);
const showNewRow = ref(false);

const newRow = ref<Record<string, unknown>>({});

function getRowKey(row: Record<string, unknown>, index: number): string {
  return String(row[props.rowKey] ?? index);
}

function handleSave(index: number, data: Record<string, unknown>): void {
  activeRowIndex.value = -1;
  emit('save', index, data);
}

function handleAdd(data: Record<string, unknown>): void {
  showNewRow.value = false;
  newRow.value = {};
  emit('add', data);
}

function handleDelete(index: number): void {
  emit('delete', index);
}
</script>
