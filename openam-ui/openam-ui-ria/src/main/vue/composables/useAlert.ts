import { reactive } from 'vue';

export interface AlertMessage {
  key?: string;
  message?: string;
  type: 'success' | 'info' | 'warning' | 'danger';
  autoDismissMs?: number;
  escape?: boolean;
  response?: AxiosErrorResponse;
}

export interface AxiosErrorResponse {
  responseJSON?: { message?: string };
  status?: number;
  statusText?: string;
}

export const TYPE_SUCCESS = 'success' as const;
export const TYPE_INFO = 'info' as const;
export const TYPE_WARNING = 'warning' as const;
export const TYPE_DANGER = 'danger' as const;

interface AlertState {
  messages: AlertMessage[];
}

const state = reactive<AlertState>({
  messages: [],
});

function extractMessageFromResponse(response: AxiosErrorResponse): string {
  if (response?.responseJSON?.message && typeof response.responseJSON.message === 'string') {
    return response.responseJSON.message;
  }
  if (response?.statusText) {
    return response.statusText;
  }
  return '';
}

function calculateDismissMs(message: AlertMessage): number | undefined {
  if (message.autoDismissMs !== undefined) {
    return message.autoDismissMs;
  }
  const text = message.message || message.key || '';
  if (message.type === 'danger') {
    return undefined;
  }
  return 2500 + text.length * 20;
}

function isDuplicate(message: AlertMessage, existing: AlertMessage): boolean {
  const msgA = message.message || message.key || '';
  const msgB = existing.message || existing.key || '';
  return msgA === msgB && msgA !== '';
}

export function useAlert() {
  function add(message: AlertMessage): void {
    const duplicate = state.messages.some((m) => isDuplicate(message, m));
    if (duplicate) {
      return;
    }

    const resolved: AlertMessage = { ...message };

    if (!resolved.message && resolved.response) {
      resolved.message = extractMessageFromResponse(resolved.response as unknown as AxiosErrorResponse);
    }

    if (!resolved.message && resolved.key) {
      resolved.message = resolved.key;
    }

    state.messages.push(resolved);

    const dismissMs = calculateDismissMs(resolved);
    if (dismissMs && dismissMs > 0) {
      setTimeout(() => {
        dismiss(resolved);
      }, dismissMs);
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

  function danger(keyOrResponse: string | AxiosErrorResponse, autoDismissMs?: number): void {
    if (typeof keyOrResponse === 'string') {
      add({ key: keyOrResponse, type: 'danger', autoDismissMs });
    } else {
      add({ type: 'danger', response: keyOrResponse, autoDismissMs });
    }
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
    TYPE_SUCCESS,
    TYPE_INFO,
    TYPE_WARNING,
    TYPE_DANGER,
  };
}
