import { config } from './config';
import { events } from './events';
import { Constants } from './constants';
import type { ThemeConfig, ThemeDefinition, ThemeMapping } from './themeConfiguration';

const DEFAULT_THEME_NAME = 'default';

function isMatchingThemeMapping(
  realm: string,
  authenticationChain: string,
  mapping: ThemeMapping,
): boolean {
  const matchers: Record<string, string> = {
    realms: realm,
    authenticationChains: authenticationChain,
  };

  for (const [key, value] of Object.entries(matchers)) {
    const patterns = mapping[key as keyof ThemeMapping];
    if (patterns === undefined) continue;
    if (!Array.isArray(patterns)) continue;
    const matched = patterns.some((pattern: string | RegExp) => {
      if (pattern instanceof RegExp) {
        return pattern.test(value);
      }
      return pattern === value;
    });
    if (!matched) return false;
  }
  return true;
}

function findMatchingTheme(
  themeConfig: ThemeConfig,
  realm: string,
  authenticationChain: string,
): string {
  if (!Array.isArray(themeConfig.mappings)) {
    return DEFAULT_THEME_NAME;
  }
  const match = themeConfig.mappings.find((m) =>
    isMatchingThemeMapping(realm, authenticationChain, m),
  );
  return match?.theme ?? DEFAULT_THEME_NAME;
}

function extendTheme(theme: ThemeDefinition, parentTheme: ThemeDefinition): ThemeDefinition {
  const result = { ...parentTheme };
  for (const [key, value] of Object.entries(theme)) {
    if (Array.isArray(value)) {
      (result as Record<string, unknown>)[key] = value;
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      (result as Record<string, unknown>)[key] = {
        ...((parentTheme as Record<string, unknown>)[key] as Record<string, unknown>),
        ...value,
      };
    } else {
      (result as Record<string, unknown>)[key] = value;
    }
  }
  return result;
}

function validateConfig(themeConfig: ThemeConfig): void {
  if (typeof themeConfig !== 'object' || themeConfig === null) {
    throw new Error('Theme configuration must return an object');
  }
  if (typeof themeConfig.themes !== 'object' || themeConfig.themes === null) {
    throw new Error('Theme configuration must specify a themes object');
  }
  if (typeof themeConfig.themes[DEFAULT_THEME_NAME] !== 'object') {
    throw new Error('Theme configuration must specify a default theme');
  }
}

function getAuthenticationChainName(): string {
  const params = new URLSearchParams(window.location.search);
  if (params.get('service')) {
    return params.get('service')!;
  }
  if (params.get('authIndexType') === 'service') {
    return params.get('authIndexValue') ?? '';
  }
  return '';
}

function applyThemeToPage(path: string, icon: string, stylesheets: readonly string[]): void {
  const head = document.head;
  const existingLinks = head.querySelectorAll('link');
  existingLinks.forEach((link) => link.remove());

  const favicon = document.createElement('link');
  favicon.rel = 'icon';
  favicon.type = 'image/x-icon';
  favicon.href = path + icon;
  head.appendChild(favicon);

  const shortcutIcon = document.createElement('link');
  shortcutIcon.rel = 'shortcut icon';
  shortcutIcon.type = 'image/x-icon';
  shortcutIcon.href = path + icon;
  head.appendChild(shortcutIcon);

  for (const stylesheet of stylesheets) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.type = 'text/css';
    link.href = stylesheet;
    head.appendChild(link);
  }
}

export function getTheme(
  themeConfig: ThemeConfig,
  realm?: string,
  isAdminTheme = false,
): ThemeDefinition {
  validateConfig(themeConfig);

  const currentRealm = realm ?? config.globalData.realm;
  const themeName = findMatchingTheme(themeConfig, currentRealm, getAuthenticationChainName());
  const hasThemeNameChanged = themeName !== config.globalData.themeName;
  const hasAdminThemeFlagChanged = isAdminTheme !== config.globalData.isAdminTheme;

  if (!hasThemeNameChanged && !hasAdminThemeFlagChanged) {
    return config.globalData.theme!;
  }

  const defaultTheme = themeConfig.themes[DEFAULT_THEME_NAME];
  let theme = themeConfig.themes[themeName];
  theme = extendTheme(theme, defaultTheme);

  const stylesheets = isAdminTheme
    ? [...Constants.DEFAULT_STYLESHEETS]
    : (theme.stylesheets ?? []);

  applyThemeToPage(theme.path ?? '', theme.icon ?? '', stylesheets);
  config.globalData.theme = theme;
  config.globalData.themeName = themeName;
  config.globalData.isAdminTheme = isAdminTheme;
  events.emit(Constants.EVENT_THEME_CHANGED);

  return theme;
}
