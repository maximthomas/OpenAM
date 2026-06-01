import { config } from '@/services/config';
import { themeConfiguration } from '@/services/themeConfiguration';
import { getTheme } from '@/services/theme';
import type { DevicePageData } from '@/types/device';

const deviceMessages = {
  common: {
    form: {
      copyright:
        "Join <a href='https://github.com/OpenIdentityPlatform/OpenAM/blob/master/README.md'>OpenAM</a> Community",
      thankYou: 'Done!',
      build: 'Build',
    },
  },
  form: {
    code: 'Enter your code here',
    description: 'Enter the code:',
    submit: 'Submit',
  },
  not_found: 'The code you entered cannot be found',
};

export const defaultPageData: DevicePageData = {
  realm: '/',
  locale: 'en',
  baseUrl: '/openam/XUI',
  done: false,
};

export function createDeviceTestWrapper(overrides?: Partial<DevicePageData>): DevicePageData {
  const pageData = { ...defaultPageData, ...overrides };

  config.globalData.realm = pageData.realm;
  config.globalData.theme = getTheme(themeConfiguration, pageData.realm, false);

  return pageData;
}

export { deviceMessages };
