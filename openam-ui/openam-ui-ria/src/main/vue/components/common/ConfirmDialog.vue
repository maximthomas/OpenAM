<template>
  <teleport to="body">
    <div
      v-if="dialogState.show"
      class="modal fade in"
      :class="{ 'modal-wide': dialogState.options.size === 'wide' }"
      tabindex="-1"
      role="dialog"
      @click.self="handleBackdropClick"
    >
      <div class="modal-dialog" :class="{ 'modal-lg': dialogState.options.size === 'wide' }">
        <div class="modal-content">
          <div class="modal-header" :class="headerClass">
            <button
              v-if="dialogState.options.closable !== false"
              type="button"
              class="close"
              @click="handleCancel"
            >
              <span>&times;</span>
            </button>
            <h4 class="modal-title">{{ dialogState.options.title }}</h4>
          </div>
          <div v-if="dialogState.options.message" class="modal-body">
            <p>{{ dialogState.options.message }}</p>
          </div>
          <div v-else class="modal-body">
            <slot />
          </div>
          <div class="modal-footer">
            <button
              type="button"
              class="btn btn-default"
              @click="handleCancel"
            >
              {{ dialogState.options.cancelText }}
            </button>
            <button
              type="button"
              :class="['btn', confirmBtnClass]"
              @click="handleConfirm"
            >
              {{ dialogState.options.confirmText }}
            </button>
          </div>
        </div>
      </div>
    </div>
    <div v-if="dialogState.show" class="modal-backdrop fade in"></div>
  </teleport>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useDialog } from '@/composables/useDialog';

const { handleConfirm, handleCancel, getDialogState } = useDialog();
const dialogState = getDialogState();

const headerClass = computed(() => {
  switch (dialogState.options.type) {
    case 'danger':
      return 'bg-danger';
    case 'warning':
      return 'bg-warning';
    default:
      return 'bg-primary';
  }
});

const confirmBtnClass = computed(() => {
  if (dialogState.options.confirmClass) {
    return dialogState.options.confirmClass;
  }
  switch (dialogState.options.type) {
    case 'danger':
      return 'btn-danger';
    case 'warning':
      return 'btn-warning';
    default:
      return 'btn-primary';
  }
});

function handleBackdropClick(): void {
  if (dialogState.options.closable !== false) {
    handleCancel();
  }
}
</script>

<style scoped>
.modal {
  display: block;
  z-index: 1060;
}

.modal-backdrop {
  z-index: 1055;
}

.modal-wide .modal-dialog {
  width: 80%;
  max-width: 900px;
}

.bg-primary {
  background-color: #337ab7;
  color: #fff;
}

.bg-danger {
  background-color: #d9534f;
  color: #fff;
}

.bg-warning {
  background-color: #f0ad4e;
  color: #fff;
}
</style>
