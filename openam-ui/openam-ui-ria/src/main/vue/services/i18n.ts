import i18n from '@/i18n';

export function t(key: string, params?: Record<string, unknown>): string {
  return i18n.global.t(key, params ?? {});
}

export function setLocale(locale: string): void {
  i18n.global.locale.value = locale;
}

export function getCurrentLocale(): string {
  return i18n.global.locale.value;
}

export function mapTranslate(map: Record<string, string>): string {
  const locale = getCurrentLocale();
  if (map[locale]) {
    return map[locale];
  }
  const fallback = (i18n.global.fallbackLocale.value as string);
  return map[fallback] ?? '';
}
