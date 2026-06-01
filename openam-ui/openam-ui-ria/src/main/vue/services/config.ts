import { reactive } from 'vue';
import type { ThemeDefinition } from './themeConfiguration';

export interface GlobalData {
  theme: ThemeDefinition | null;
  themeName: string;
  isAdminTheme: boolean;
  realm: string;
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
  },
});
