import { describe, it, expect } from 'vitest';
import { themeConfiguration } from '@/services/themeConfiguration';

describe('themeConfiguration', () => {
  it('has a default theme', () => {
    expect(themeConfiguration.themes.default).toBeDefined();
    expect(themeConfiguration.themes.default.stylesheets).toBeDefined();
    expect(themeConfiguration.themes.default.icon).toBeDefined();
  });

  it('has default theme stylesheets', () => {
    expect(themeConfiguration.themes.default.stylesheets).toContain('css/structure.css');
    expect(themeConfiguration.themes.default.stylesheets).toContain('css/theme.css');
  });

  it('has mappings array', () => {
    expect(Array.isArray(themeConfiguration.mappings)).toBe(true);
  });

  it('has fr-dark-theme', () => {
    expect(themeConfiguration.themes['fr-dark-theme']).toBeDefined();
    expect(themeConfiguration.themes['fr-dark-theme'].stylesheets).toContain(
      'themes/dark/css/theme-dark.css',
    );
  });

  it('has logo settings on default theme', () => {
    expect(themeConfiguration.themes.default.settings?.logo).toBeDefined();
    expect(themeConfiguration.themes.default.settings?.loginLogo).toBeDefined();
  });
});
