import { reactive } from 'vue';
import type { ThemeDefinition } from './themeConfiguration';

export interface AuthConfig {
  cookieName: string;
  cookieDomains: string[];
  cookieSameSite: string;
  secureCookie: boolean;
  zeroPageLogin: {
    enabled: boolean;
    allowedWithoutReferer: boolean;
    refererWhitelist: string[];
  };
  forgotPassword: boolean;
  forgotUsername: boolean;
  selfRegistration: boolean;
  socialImplementations: Array<{
    displayName: string;
    icon: string;
    oauth: { authorizationEndpoint: string; [key: string]: unknown };
  }>;
  currentStage: number;
  urlParams: Record<string, string>;
  fullLoginURL: string;
  subRealm: string;
}

export interface GlobalData {
  theme: ThemeDefinition | null;
  themeName: string;
  isAdminTheme: boolean;
  realm: string;
  version: string;
  auth: AuthConfig;
}

export interface Config {
  host: string;
  globalData: GlobalData;
}

export const config = reactive<Config>({
  host: '',
  globalData: {
    theme: null,
    themeName: '',
    isAdminTheme: false,
    realm: '/',
    version: '',
    auth: {
      cookieName: 'iPlanetDirectoryPro',
      cookieDomains: [],
      cookieSameSite: 'none',
      secureCookie: false,
      zeroPageLogin: {
        enabled: false,
        allowedWithoutReferer: false,
        refererWhitelist: [],
      },
      forgotPassword: false,
      forgotUsername: false,
      selfRegistration: false,
      socialImplementations: [],
      currentStage: 0,
      urlParams: {},
      fullLoginURL: '',
      subRealm: '',
    },
  },
});
