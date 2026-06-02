import { config } from '@/services/config';
import { themeConfiguration } from '@/services/themeConfiguration';
import { getTheme } from '@/services/theme';
import type { AuthorizePageData } from '@/types/authorize';

const authorizeMessages = {
  common: {
    form: {
      copyright:
        "Join <a href='https://github.com/OpenIdentityPlatform/OpenAM/blob/master/README.md'>OpenAM</a> Community",
      build: 'Build',
    },
  },
  form: {
    description: 'This application is requesting the following private information:',
    noScopes: 'This application is requesting access to your account',
    signedInAs: 'You are signed in as:',
    save: 'Save Consent',
    allow: 'Allow',
    deny: 'Deny',
  },
};

export const defaultPageData: AuthorizePageData = {
  realm: '/',
  locale: 'en',
  baseUrl: '/openam/XUI',
  oauth2Data: {
    displayName: 'Test App',
    displayScopes: [],
    displayClaims: [],
    formTarget: '/authorize/consent',
    responseType: 'code',
    clientId: 'test-client',
    csrf: 'mock-csrf',
  },
};

export function createAuthorizeTestWrapper(overrides?: Partial<AuthorizePageData>): AuthorizePageData {
  const pageData = { ...defaultPageData, ...overrides };

  config.globalData.realm = pageData.realm;
  config.globalData.theme = getTheme(themeConfiguration, pageData.realm, false);

  return pageData;
}

export { authorizeMessages };
