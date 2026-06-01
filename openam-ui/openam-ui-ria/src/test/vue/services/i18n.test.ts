import { describe, it, expect, vi, beforeEach } from 'vitest';

const { locale } = vi.hoisted(() => ({ locale: { value: 'en' } }));

vi.mock('@/i18n', () => ({
  default: {
    global: {
      t: vi.fn((key: string) => `translated:${key}`),
      locale,
      fallbackLocale: { value: 'en' },
    },
  },
}));

import { t, setLocale, getCurrentLocale, mapTranslate } from '@/services/i18n';
import i18n from '@/i18n';

describe('i18n', () => {
  beforeEach(() => {
    locale.value = 'en';
  });

  it('t wraps vue-i18n t', () => {
    const result = t('some.key');
    expect(result).toBe('translated:some.key');
    expect(i18n.global.t).toHaveBeenCalledWith('some.key', {});
  });

  it('setLocale changes locale', () => {
    setLocale('fr');
    expect(locale.value).toBe('fr');
  });

  it('getCurrentLocale returns current locale', () => {
    expect(getCurrentLocale()).toBe('en');
  });

  it('mapTranslate returns locale match', () => {
    const map: Record<string, string> = {
      en: 'Hello',
      fr: 'Bonjour',
    };
    const result = mapTranslate(map);
    expect(result).toBe('Hello');
  });
});
