import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useAlert } from '@/composables/useAlert';

describe('useAlert', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    const { dismissAll } = useAlert();
    dismissAll();
  });

  it('adds a message with key', () => {
    const { add, messages } = useAlert();
    add({ key: 'test.message', type: 'info' });
    expect(messages).toHaveLength(1);
    expect(messages[0].key).toBe('test.message');
  });

  it('adds a message with raw message', () => {
    const { add, messages } = useAlert();
    add({ message: 'Server error occurred', type: 'danger' });
    expect(messages).toHaveLength(1);
    expect(messages[0].message).toBe('Server error occurred');
  });

  it('extracts message from response object', () => {
    const { add, messages } = useAlert();
    add({
      type: 'danger',
      response: { responseJSON: { message: 'Session expired' } },
    });
    expect(messages).toHaveLength(1);
    expect(messages[0].message).toBe('Session expired');
  });

  it('falls back to statusText when responseJSON.message is missing', () => {
    const { add, messages } = useAlert();
    add({
      type: 'danger',
      response: { statusText: 'Not Found', status: 404 },
    });
    expect(messages).toHaveLength(1);
    expect(messages[0].message).toBe('Not Found');
  });

  it('deduplicates messages with same text', () => {
    const { add, messages } = useAlert();
    add({ message: 'Duplicate error', type: 'danger' });
    add({ message: 'Duplicate error', type: 'danger' });
    expect(messages).toHaveLength(1);
  });

  it('does not deduplicate messages with different text', () => {
    const { add, messages } = useAlert();
    add({ message: 'Error one', type: 'danger' });
    add({ message: 'Error two', type: 'danger' });
    expect(messages).toHaveLength(2);
  });

  it('does not auto-dismiss danger messages', () => {
    const { add, messages } = useAlert();
    add({ key: 'error', type: 'danger' });
    vi.advanceTimersByTime(10000);
    expect(messages).toHaveLength(1);
  });

  it('auto-dismisses non-danger messages with formula 2500 + length * 20', () => {
    const { add, messages } = useAlert();
    add({ message: 'Hello', type: 'info' });
    expect(messages).toHaveLength(1);
    vi.advanceTimersByTime(2500 + 5 * 20);
    expect(messages).toHaveLength(0);
  });

  it('dismisses a specific message', () => {
    const { add, dismiss, messages } = useAlert();
    add({ message: 'Error', type: 'danger' });
    expect(messages).toHaveLength(1);
    dismiss(messages[0]);
    expect(messages).toHaveLength(0);
  });

  it('dismissAll clears all messages', () => {
    const { add, dismissAll, messages } = useAlert();
    add({ message: 'Error 1', type: 'danger' });
    add({ message: 'Error 2', type: 'danger' });
    dismissAll();
    expect(messages).toHaveLength(0);
  });

  it('success() adds a success message', () => {
    const { success, messages } = useAlert();
    success('test.success');
    expect(messages).toHaveLength(1);
    expect(messages[0].type).toBe('success');
    expect(messages[0].key).toBe('test.success');
  });

  it('danger() adds a danger message with string key', () => {
    const { danger, messages } = useAlert();
    danger('test.error');
    expect(messages).toHaveLength(1);
    expect(messages[0].type).toBe('danger');
    expect(messages[0].key).toBe('test.error');
  });

  it('danger() adds a danger message with response object', () => {
    const { danger, messages } = useAlert();
    danger({ responseJSON: { message: 'Auth failed' } });
    expect(messages).toHaveLength(1);
    expect(messages[0].type).toBe('danger');
    expect(messages[0].message).toBe('Auth failed');
  });

  it('exposes type constants', () => {
    const { TYPE_SUCCESS, TYPE_INFO, TYPE_WARNING, TYPE_DANGER } = useAlert();
    expect(TYPE_SUCCESS).toBe('success');
    expect(TYPE_INFO).toBe('info');
    expect(TYPE_WARNING).toBe('warning');
    expect(TYPE_DANGER).toBe('danger');
  });
});
