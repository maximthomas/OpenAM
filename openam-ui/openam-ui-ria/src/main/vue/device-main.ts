import { createApp } from 'vue';
import DeviceApp from '@/views/device/DeviceApp.vue';
import { configureI18n } from '@/i18n';
import { getTheme } from '@/services/theme';
import { themeConfiguration } from '@/services/themeConfiguration';
import type { DevicePageData } from '@/types/device';

async function bootstrap(): Promise<void> {
  const pageData: DevicePageData = window.pageData ?? {
    realm: '/',
    locale: 'en',
    baseUrl: '/openam/XUI',
    done: false,
  };

  window.pageData = pageData;

  await configureI18n(pageData.baseUrl, 'device', pageData);

  getTheme(themeConfiguration, pageData.realm, false);

  const app = createApp(DeviceApp, { pageData });
  app.mount('#wrapper');

  document.body.style.display = '';
}

bootstrap();
