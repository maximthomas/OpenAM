type Handler = (...args: unknown[]) => void;

const handlers = new Map<string, Set<Handler>>();

export const events = {
  on(event: string, handler: Handler): void {
    if (!handlers.has(event)) {
      handlers.set(event, new Set());
    }
    handlers.get(event)!.add(handler);
  },

  off(event: string, handler: Handler): void {
    handlers.get(event)?.delete(handler);
  },

  emit(event: string, ...args: unknown[]): void {
    handlers.get(event)?.forEach((handler) => handler(...args));
  },

  once(event: string, handler: Handler): void {
    const wrapper = (...args: unknown[]) => {
      events.off(event, wrapper);
      handler(...args);
    };
    events.on(event, wrapper);
  },
};
