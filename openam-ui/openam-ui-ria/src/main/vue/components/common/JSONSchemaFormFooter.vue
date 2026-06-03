<template>
  <div class="form-group">
    <hr />
    <div class="text-right">
      <button
        type="button"
        class="btn btn-default"
        @click="$emit('revert')"
      >
        {{ t('common.form.revert') }}
      </button>
      <button
        type="button"
        class="btn btn-primary"
        @click="$emit('save')"
      >
        {{ t('common.form.save') }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n';

const { t } = useI18n();

defineEmits<{
  save: [];
  revert: [];
}>();
</script>
