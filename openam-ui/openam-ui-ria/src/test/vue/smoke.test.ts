import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createMemoryHistory } from 'vue-router';
import App from '@/App.vue';
import i18n from '@/i18n';

const router = createRouter({
  history: createMemoryHistory(),
  routes: [{ path: '/', component: { template: '<div />' } }],
});

describe('App', () => {
  it('mounts without error', () => {
    const wrapper = mount(App, {
      global: {
        plugins: [router, i18n],
        stubs: {
          'router-view': true,
          AppHeader: true,
          AppFooter: true,
          AlertContainer: true,
        },
      },
    });
    expect(wrapper.exists()).toBe(true);
  });
});
