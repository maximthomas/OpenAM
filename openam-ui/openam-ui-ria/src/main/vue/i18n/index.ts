import { createI18n } from 'vue-i18n';

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: {},
  messageCompiler: (message) => () => message,
});

export default i18n;

export async function configureI18n(
  basePath: string,
  namespace: string,
  pageData: { locale?: string },
): Promise<void> {
  const locale = pageData.locale ?? 'en';

  try {
    const response = await fetch(
      `${basePath}/locales/${locale}/${namespace}.json`,
    );
    if (response.ok) {
      const messages = await response.json();
      i18n.global.setLocaleMessage(locale, messages);
      i18n.global.locale.value = locale;
    }
  } catch {
    // Silently degrade — translations will be empty
  }
}
