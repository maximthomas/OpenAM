import { describe, it, expect, beforeEach } from 'vitest';
import { config } from '@/services/config';

describe('config', () => {
  beforeEach(() => {
    config.host = '';
    config.globalData.theme = null;
    config.globalData.themeName = '';
    config.globalData.isAdminTheme = false;
    config.globalData.realm = '/';
  });

  it('has default host', () => {
    expect(config.host).toBe('');
  });

  it('has default globalData', () => {
    expect(config.globalData.theme).toBeNull();
    expect(config.globalData.themeName).toBe('');
    expect(config.globalData.isAdminTheme).toBe(false);
    expect(config.globalData.realm).toBe('/');
  });

  it('is reactive', () => {
    config.globalData.realm = '/test';
    expect(config.globalData.realm).toBe('/test');
  });

  it('allows setting theme', () => {
    const theme = { stylesheets: ['test.css'] };
    config.globalData.theme = theme as never;
    expect(config.globalData.theme).toEqual(theme);
  });
});
