<template>
  <tr :class="{ 'editing': editing }">
    <template v-if="!editing">
      <td v-for="col in columns" :key="col">{{ row[col] }}</td>
      <td class="text-right">
        <button
          type="button"
          class="btn btn-link btn-xs"
          @click="$emit('edit')"
        >
          <i class="fa fa-pencil"></i>
        </button>
        <button
          type="button"
          class="btn btn-link btn-xs text-danger"
          @click="$emit('delete')"
        >
          <i class="fa fa-trash-o"></i>
        </button>
      </td>
    </template>
    <template v-else>
      <td v-for="col in columns" :key="col">
        <select
          v-if="isEnum(col)"
          class="form-control input-sm"
          :value="editData[col]"
          @change="editData[col] = ($event.target as HTMLSelectElement).value"
        >
          <option
            v-for="opt in getEnumOptions(col)"
            :key="opt"
            :value="opt"
          >
            {{ opt }}
          </option>
        </select>
        <input
          v-else
          type="text"
          class="form-control input-sm"
          :value="editData[col]"
          @input="editData[col] = ($event.target as HTMLInputElement).value"
          @keyup.enter="handleSave"
          @keyup.escape="$emit('cancel')"
        />
      </td>
      <td class="text-right">
        <button
          type="button"
          class="btn btn-link btn-xs"
          @click="handleSave"
        >
          <i class="fa fa-check"></i>
        </button>
        <button
          type="button"
          class="btn btn-link btn-xs"
          @click="$emit('cancel')"
        >
          <i class="fa fa-times"></i>
        </button>
      </td>
    </template>
  </tr>
</template>

<script setup lang="ts">
import { ref, reactive, watch } from 'vue';

interface RowSchemaProperty {
  type?: string;
  enum?: string[];
  required?: boolean;
}

const props = defineProps<{
  row: Record<string, unknown>;
  columns: string[];
  editing: boolean;
  rowSchema?: Record<string, RowSchemaProperty>;
}>();

const emit = defineEmits<{
  edit: [];
  save: [data: Record<string, unknown>];
  cancel: [];
  delete: [];
}>();

const editData = reactive<Record<string, unknown>>({ ...props.row });

watch(
  () => props.row,
  (newRow) => {
    Object.assign(editData, newRow);
  }
);

watch(
  () => props.editing,
  (isEditing) => {
    if (isEditing) {
      Object.assign(editData, props.row);
    }
  }
);

function isEnum(col: string): boolean {
  return Boolean(props.rowSchema?.[col]?.enum);
}

function getEnumOptions(col: string): string[] {
  return (props.rowSchema?.[col]?.enum as string[]) || [];
}

function handleSave(): void {
  emit('save', { ...editData });
}
</script>
