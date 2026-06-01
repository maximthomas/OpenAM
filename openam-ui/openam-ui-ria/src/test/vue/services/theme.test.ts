import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getTheme } from '@/services/theme';
import { config } from '@/services/config';
import { events } from '@/services/events';
import { Constants } from '@/services/constants';
import type { ThemeConfig } from '@/services/themeConfiguration';

const testThemeConfig: ThemeConfig = {
  themes: {
    default: {
      stylesheets: ['a.css', 'c.css'],
      path: '',
      icon: 'icon.png',
      settings: {
        logo: { src: 'foo' },
        loginLogo: { src: 'bar' },
      },
    },
    other: {
      stylesheets: ['b.css'],
      path: '',
      icon: 'otherIcon.png',
    },
  },
  mappings: [{ theme: 'other', realms: ['/b'] }],
};

describe('theme', () => {
  beforeEach(() => {
    config.globalData.realm = '/';
    config.globalData.theme = null;
    config.globalData.themeName = '';
    config.globalData.isAdminTheme = false;
    document.head.innerHTML = '';
  });

  it('selects default theme for unmatched realm', () => {
    const theme = getTheme(testThemeConfig, '/');
    expect(theme.stylesheets).toEqual(['a.css', 'c.css']);
    expect(config.globalData.themeName).toBe('default');
  });

  it('selects correct theme based on realm', () => {
    const theme = getTheme(testThemeConfig, '/b');
    expect(theme.stylesheets).toEqual(['b.css']);
    expect(config.globalData.themeName).toBe('other');
  });

  it('selects default theme if no realms match', () => {
    const theme = getTheme(testThemeConfig, '/c');
    expect(theme.stylesheets).toEqual(['a.css', 'c.css']);
  });

  it('allows mappings with regex', () => {
    const config: ThemeConfig = {
      themes: testThemeConfig.themes,
      mappings: [{ theme: 'other', realms: [/^\/hello.*/] }],
    };
    const theme = getTheme(config, '/hello/world');
    expect(theme.stylesheets).toEqual(['b.css']);
  });

  it('fills missing properties from default theme', () => {
    const configWithMissing: ThemeConfig = {
      themes: {
        default: { stylesheets: ['a.css'], path: '', icon: 'icon.png' },
        other: { path: '', icon: 'other.png' },
      },
      mappings: [{ theme: 'other', realms: ['/b'] }],
    };
    const theme = getTheme(configWithMissing, '/b');
    expect(theme.stylesheets).toEqual(['a.css']);
    expect(theme.icon).toBe('other.png');
  });

  it('does not merge arrays', () => {
    const theme = getTheme(testThemeConfig, '/b');
    expect(theme.stylesheets).toEqual(['b.css']);
  });

  it('overrides stylesheets for admin theme', () => {
    getTheme(testThemeConfig, '/', true);
    const links = document.querySelectorAll('link[rel="stylesheet"]');
    expect(links.length).toBe(Constants.DEFAULT_STYLESHEETS.length);
  });

  it('adds favicon to page', () => {
    getTheme(testThemeConfig, '/');
    const favicon = document.querySelector('link[rel="icon"]');
    expect(favicon).not.toBeNull();
    expect(favicon?.getAttribute('href')).toBe('icon.png');
  });

  it('adds shortcut icon to page', () => {
    getTheme(testThemeConfig, '/');
    const shortcut = document.querySelector('link[rel="shortcut icon"]');
    expect(shortcut).not.toBeNull();
    expect(shortcut?.getAttribute('href')).toBe('icon.png');
  });

  it('emits EVENT_THEME_CHANGED', () => {
    const handler = vi.fn();
    events.on(Constants.EVENT_THEME_CHANGED, handler);
    getTheme(testThemeConfig, '/');
    expect(handler).toHaveBeenCalledOnce();
    events.off(Constants.EVENT_THEME_CHANGED, handler);
  });

  it('removes existing links before applying theme', () => {
    const existing = document.createElement('link');
    existing.rel = 'stylesheet';
    document.head.appendChild(existing);
    getTheme(testThemeConfig, '/');
    const links = document.querySelectorAll('link');
    const existingStillThere = Array.from(links).includes(existing);
    expect(existingStillThere).toBe(false);
  });

  it('updates src fields relative to entry point', () => {
    const theme = getTheme(testThemeConfig, '/');
    expect(theme.settings?.logo?.src).toBe('foo');
    expect(theme.settings?.loginLogo?.src).toBe('bar');
  });

  it('throws if themes object missing', () => {
    expect(() => getTheme({ themes: {} } as ThemeConfig, '/')).toThrow();
  });

  it('throws if default theme missing', () => {
    const badConfig: ThemeConfig = { themes: { other: {} } };
    expect(() => getTheme(badConfig, '/')).toThrow();
  });
});
