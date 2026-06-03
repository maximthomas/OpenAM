<template>
  <div class="select-input" ref="containerEl">
    <div class="input-group">
      <input
        type="text"
        class="form-control"
        :placeholder="placeholder"
        :value="displayValue"
        @input="onSearch"
        @focus="showDropdown = true"
        @blur="onBlur"
        @keydown.enter.prevent="onEnter"
        @keydown.escape="onEscape"
        @keydown.arrow-down.prevent="onArrowDown"
        @keydown.arrow-up.prevent="onArrowUp"
      />
      <span v-if="displayValue" class="input-group-btn">
        <button
          type="button"
          class="btn btn-default"
          @click="clearSelection"
        >
          <i class="fa fa-times"></i>
        </button>
      </span>
    </div>
    <ul v-if="showDropdown && filteredOptions.length > 0" class="dropdown-menu show">
      <li
        v-for="(option, index) in filteredOptions"
        :key="index"
        :class="{ active: highlightedIndex === index }"
      >
        <a
          href="#"
          @mousedown.prevent="selectOption(option)"
          @mouseenter="highlightedIndex = index"
        >
          <slot name="option" :option="option">
            {{ getLabel(option) }}
          </slot>
        </a>
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';

const props = withDefaults(
  defineProps<{
    options: Array<Record<string, unknown>>;
    value?: Record<string, unknown> | null;
    searchFields?: string[];
    labelField?: string;
    placeholder?: string;
  }>(),
  {
    searchFields: () => [],
    labelField: '',
    placeholder: 'Select...',
    value: null,
  }
);

const emit = defineEmits<{
  'update:value': [value: Record<string, unknown>];
}>();

const containerEl = ref<HTMLDivElement>();
const searchText = ref('');
const showDropdown = ref(false);
const highlightedIndex = ref(-1);

const displayValue = computed(() => {
  if (searchText.value) {
    return searchText.value;
  }
  if (props.value) {
    return getLabel(props.value);
  }
  return '';
});

const filteredOptions = computed(() => {
  if (!searchText.value) {
    return props.options;
  }
  const query = searchText.value.toLowerCase();
  return props.options.filter((option) =>
    props.searchFields.some((field) => {
      const val = option[field];
      return val && String(val).toLowerCase().includes(query);
    })
  );
});

function getLabel(option: Record<string, unknown>): string {
  if (props.labelField && option[props.labelField] !== undefined) {
    return String(option[props.labelField]);
  }
  if (option.name !== undefined) {
    return String(option.name);
  }
  if (option._id !== undefined) {
    return String(option._id);
  }
  return JSON.stringify(option);
}

function onSearch(event: Event): void {
  searchText.value = (event.target as HTMLInputElement).value;
  showDropdown.value = true;
  highlightedIndex.value = 0;
}

function selectOption(option: Record<string, unknown>): void {
  emit('update:value', option);
  searchText.value = '';
  showDropdown.value = false;
  highlightedIndex.value = -1;
}

function clearSelection(): void {
  emit('update:value', null as unknown as Record<string, unknown>);
  searchText.value = '';
}

function onBlur(): void {
  setTimeout(() => {
    showDropdown.value = false;
    searchText.value = '';
  }, 200);
}

function onEscape(): void {
  showDropdown.value = false;
  searchText.value = '';
}

function onEnter(): void {
  if (highlightedIndex.value >= 0 && filteredOptions.value[highlightedIndex.value]) {
    selectOption(filteredOptions.value[highlightedIndex.value]);
  }
}

function onArrowDown(): void {
  if (highlightedIndex.value < filteredOptions.value.length - 1) {
    highlightedIndex.value++;
  }
}

function onArrowUp(): void {
  if (highlightedIndex.value > 0) {
    highlightedIndex.value--;
  }
}
</script>

<style scoped>
.select-input {
  position: relative;
}

.select-input .dropdown-menu {
  display: block;
  max-height: 200px;
  overflow-y: auto;
  width: 100%;
}
</style>
