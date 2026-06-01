import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { createI18n } from 'vue-i18n';
import DeviceForm from '@/views/device/DeviceForm.vue';
import DeviceDone from '@/views/device/DeviceDone.vue';
import DeviceError from '@/views/device/DeviceError.vue';
import DeviceApp from '@/views/device/DeviceApp.vue';
import { createDeviceTestWrapper, deviceMessages } from '../helpers/device';

function createTestI18n() {
  return createI18n({
    legacy: false,
    locale: 'en',
    fallbackLocale: 'en',
    messages: { en: deviceMessages },
  });
}

describe('DeviceForm', () => {
  it('renders form with correct method and autocomplete', () => {
    const wrapper = mount(DeviceForm, {
      global: { plugins: [createTestI18n()] },
    });

    const form = wrapper.find('form');
    expect(form.attributes('method')).toBe('post');
    expect(form.attributes('autocomplete')).toBe('off');
    expect(form.attributes('aria-describedby')).toBe('deviceFormInfo');
  });

  it('renders user_code input with required attributes', () => {
    const wrapper = mount(DeviceForm, {
      global: { plugins: [createTestI18n()] },
    });

    const input = wrapper.find('input[name="user_code"]');
    expect(input.exists()).toBe(true);
    expect(input.attributes('id')).toBe('deviceUserCode');
    expect(input.attributes('required')).toBeDefined();
    expect(input.attributes('class')).toContain('form-control');
    expect(input.attributes('placeholder')).toBe('Enter your code here');
  });

  it('renders submit button', () => {
    const wrapper = mount(DeviceForm, {
      global: { plugins: [createTestI18n()] },
    });

    const button = wrapper.find('button[type="submit"]');
    expect(button.exists()).toBe(true);
    expect(button.text()).toBe('Submit');
    expect(button.attributes('class')).toContain('btn-primary');
  });

  it('renders screen-reader-only label for the input', () => {
    const wrapper = mount(DeviceForm, {
      global: { plugins: [createTestI18n()] },
    });

    const label = wrapper.find('label[for="deviceUserCode"]');
    expect(label.exists()).toBe(true);
    expect(label.attributes('class')).toContain('sr-only');
    expect(label.text()).toBe('Enter your code here');
  });

  it('renders form description paragraph', () => {
    const wrapper = mount(DeviceForm, {
      global: { plugins: [createTestI18n()] },
    });

    const description = wrapper.find('#deviceFormInfo');
    expect(description.exists()).toBe(true);
    expect(description.text()).toBe('Enter the code:');
  });
});

describe('DeviceDone', () => {
  it('renders thank you message in jumbotron', () => {
    const wrapper = mount(DeviceDone, {
      global: { plugins: [createTestI18n()] },
    });

    const jumbotron = wrapper.find('.jumbotron');
    expect(jumbotron.exists()).toBe(true);
    expect(jumbotron.classes()).toContain('text-center');

    const h1 = wrapper.find('h1');
    expect(h1.text()).toBe('Done!');
  });
});

describe('DeviceError', () => {
  it('renders error alert with translated error code', () => {
    const wrapper = mount(DeviceError, {
      props: { errorCode: 'not_found' },
      global: { plugins: [createTestI18n()] },
    });

    const alert = wrapper.find('.alert');
    expect(alert.exists()).toBe(true);
    expect(alert.classes()).toContain('alert-warning');
    expect(alert.attributes('role')).toBe('alert');
    expect(alert.find('strong').text()).toBe(
      'The code you entered cannot be found',
    );
  });
});

describe('DeviceApp', () => {
  it('renders DeviceForm when no done or errorCode', () => {
    const pageData = createDeviceTestWrapper();
    const wrapper = mount(DeviceApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.findComponent(DeviceForm).exists()).toBe(true);
    expect(wrapper.findComponent(DeviceDone).exists()).toBe(false);
    expect(wrapper.findComponent(DeviceError).exists()).toBe(false);
  });

  it('renders DeviceDone when pageData.done is true', () => {
    const pageData = createDeviceTestWrapper({ done: true });
    const wrapper = mount(DeviceApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.findComponent(DeviceDone).exists()).toBe(true);
    expect(wrapper.findComponent(DeviceForm).exists()).toBe(false);
  });

  it('renders DeviceError when pageData.errorCode is set', () => {
    const pageData = createDeviceTestWrapper({ errorCode: 'not_found' });
    const wrapper = mount(DeviceApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.findComponent(DeviceError).exists()).toBe(true);
    expect(wrapper.findComponent(DeviceForm).exists()).toBe(false);
    expect(wrapper.findComponent(DeviceDone).exists()).toBe(false);
  });

  it('renders login-base structure with logo holder and content div', () => {
    const pageData = createDeviceTestWrapper();
    const wrapper = mount(DeviceApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.find('#login-base').exists()).toBe(true);
    expect(wrapper.find('#loginBaseLogo').exists()).toBe(true);
    expect(wrapper.find('#content').exists()).toBe(true);
  });

  it('renders login logo height spacer when theme provides height', () => {
    const pageData = createDeviceTestWrapper();
    const wrapper = mount(DeviceApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    const spacer = wrapper.find('#loginBaseLogo > div');
    expect(spacer.exists()).toBe(true);
    expect(spacer.attributes('style')).toContain('height');
  });
});
