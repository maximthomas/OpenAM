import { reactive } from 'vue';

export interface AlertMessage {
  key: string;
  type: 'success' | 'info' | 'warning' | 'danger';
  autoDismissMs?: number;
}

interface AlertState {
  messages: AlertMessage[];
}

const state = reactive<AlertState>({
  messages: [],
});

let idCounter = 0;

export function useAlert() {
  function add(message: AlertMessage): void {
    state.messages.push(message);

    if (message.autoDismissMs && message.autoDismissMs > 0) {
      setTimeout(() => {
        dismiss(message);
      }, message.autoDismissMs);
    }
  }

  function dismiss(message: AlertMessage): void {
    const index = state.messages.indexOf(message);
    if (index !== -1) {
      state.messages.splice(index, 1);
    }
  }

  function dismissAll(): void {
    state.messages.splice(0);
  }

  function success(key: string, autoDismissMs = 5000): void {
    add({ key, type: 'success', autoDismissMs });
  }

  function info(key: string, autoDismissMs = 5000): void {
    add({ key, type: 'info', autoDismissMs });
  }

  function warning(key: string, autoDismissMs = 5000): void {
    add({ key, type: 'warning', autoDismissMs });
  }

  function danger(key: string, autoDismissMs?: number): void {
    add({ key, type: 'danger', autoDismissMs });
  }

  return {
    messages: state.messages,
    add,
    dismiss,
    dismissAll,
    success,
    info,
    warning,
    danger,
  };
}
