import { createApp } from 'vue';
import AuthorizeApp from '@/views/authorize/AuthorizeApp.vue';
import i18n, { configureI18n } from '@/i18n';
import { getTheme } from '@/services/theme';
import { themeConfiguration } from '@/services/themeConfiguration';
import { getUserSessionId } from '@/services/oauth2';
import type { AuthorizePageData } from '@/types/authorize';

function isEmptyValues(values: unknown): boolean {
  if (values == null) return true;
  if (typeof values === 'string') return values.length === 0;
  if (Array.isArray(values)) return values.length === 0;
  if (typeof values === 'object') return Object.keys(values).length === 0;
  return true;
}

function cleanValues(pageData: AuthorizePageData): void {
  if (!pageData.oauth2Data) return;

  for (const scope of pageData.oauth2Data.displayScopes) {
    if (isEmptyValues(scope.values)) {
      delete scope.values;
    }
  }
  for (const claim of pageData.oauth2Data.displayClaims) {
    if (isEmptyValues(claim.values)) {
      delete claim.values;
    }
  }

  if (
    pageData.oauth2Data.displayScopes.length === 0 &&
    pageData.oauth2Data.displayClaims.length === 0
  ) {
    pageData.noScopes = true;
  }
}

async function bootstrap(): Promise<void> {
  const pageData: AuthorizePageData = window.pageData ?? {
    realm: '/',
    baseUrl: '/openam/XUI',
  };

  window.pageData = pageData;

  cleanValues(pageData);

  if (pageData.oauth2Data) {
    const csrf = await getUserSessionId();
    pageData.oauth2Data.csrf = csrf;
  } else {
    pageData.noScopes = true;
  }

  await configureI18n(pageData.baseUrl, 'authorize', pageData);

  getTheme(themeConfiguration, pageData.realm, false);

  const app = createApp(AuthorizeApp, { pageData });
  app.use(i18n);
  app.mount('#wrapper');

  document.body.style.display = '';
}

bootstrap();
