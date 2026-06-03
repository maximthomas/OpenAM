import { reactive } from 'vue';

export interface DialogOptions {
  title: string;
  message?: string;
  type?: 'primary' | 'danger' | 'warning';
  size?: 'normal' | 'wide';
  closable?: boolean;
  confirmText?: string;
  cancelText?: string;
  confirmClass?: string;
}

interface DialogState {
  show: boolean;
  options: DialogOptions;
  resolve: ((value: boolean) => void) | null;
}

const state = reactive<DialogState>({
  show: false,
  options: {
    title: '',
    type: 'primary',
    size: 'normal',
    closable: true,
    confirmText: 'OK',
    cancelText: 'Cancel',
  },
  resolve: null,
});

export function useDialog() {
  function confirm(options: DialogOptions): Promise<boolean> {
    return new Promise((resolve) => {
      state.options = {
        type: 'primary',
        size: 'normal',
        closable: true,
        confirmText: 'OK',
        cancelText: 'Cancel',
        ...options,
      };
      state.resolve = resolve;
      state.show = true;
    });
  }

  function handleConfirm(): void {
    state.show = false;
    state.resolve?.(true);
    state.resolve = null;
  }

  function handleCancel(): void {
    state.show = false;
    state.resolve?.(false);
    state.resolve = null;
  }

  function getDialogState(): DialogState {
    return state;
  }

  return {
    confirm,
    handleConfirm,
    handleCancel,
    getDialogState,
  };
}
