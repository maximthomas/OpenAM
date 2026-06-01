import { describe, it, expect, vi } from 'vitest';
import { events } from '@/services/events';

describe('events', () => {
  it('calls handler when event is emitted', () => {
    const handler = vi.fn();
    events.on('test', handler);
    events.emit('test');
    expect(handler).toHaveBeenCalledOnce();
  });

  it('passes arguments to handler', () => {
    const handler = vi.fn();
    events.on('test', handler);
    events.emit('test', 'arg1', 42);
    expect(handler).toHaveBeenCalledWith('arg1', 42);
  });

  it('supports multiple handlers for same event', () => {
    const handler1 = vi.fn();
    const handler2 = vi.fn();
    events.on('test', handler1);
    events.on('test', handler2);
    events.emit('test');
    expect(handler1).toHaveBeenCalledOnce();
    expect(handler2).toHaveBeenCalledOnce();
  });

  it('removes handler with off', () => {
    const handler = vi.fn();
    events.on('test', handler);
    events.off('test', handler);
    events.emit('test');
    expect(handler).not.toHaveBeenCalled();
  });

  it('once fires handler only once', () => {
    const handler = vi.fn();
    events.once('test', handler);
    events.emit('test');
    events.emit('test');
    expect(handler).toHaveBeenCalledOnce();
  });

  it('does not call handlers for different events', () => {
    const handler = vi.fn();
    events.on('testA', handler);
    events.emit('testB');
    expect(handler).not.toHaveBeenCalled();
  });

  it('handles emit with no handlers gracefully', () => {
    expect(() => events.emit('nonexistent')).not.toThrow();
  });
});
