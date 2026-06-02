import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { createI18n } from 'vue-i18n';
import ErrorDisplay from '@/views/authorize/ErrorDisplay.vue';
import ScopeList from '@/views/authorize/ScopeList.vue';
import AuthorizeForm from '@/views/authorize/AuthorizeForm.vue';
import AuthorizeApp from '@/views/authorize/AuthorizeApp.vue';
import { createAuthorizeTestWrapper, authorizeMessages } from '../helpers/authorize';

function createTestI18n() {
  return createI18n({
    legacy: false,
    locale: 'en',
    fallbackLocale: 'en',
    messages: { en: authorizeMessages },
  });
}

describe('ErrorDisplay', () => {
  it('renders error message in strong tag', () => {
    const wrapper = mount(ErrorDisplay, {
      props: { error: { message: 'Access denied' } },
    });

    const alert = wrapper.find('.alert');
    expect(alert.exists()).toBe(true);
    expect(alert.classes()).toContain('alert-warning');
    expect(alert.attributes('role')).toBe('alert');
    expect(alert.find('strong').text()).toBe('Access denied');
  });

  it('renders error message as link when uri is provided', () => {
    const wrapper = mount(ErrorDisplay, {
      props: { error: { uri: 'https://example.com', message: 'Error' } },
    });

    const link = wrapper.find('a');
    expect(link.exists()).toBe(true);
    expect(link.attributes('href')).toBe('https://example.com');
    expect(link.text()).toBe('Error');
  });

  it('renders description when provided', () => {
    const wrapper = mount(ErrorDisplay, {
      props: { error: { message: 'Error', description: 'Something went wrong' } },
    });

    expect(wrapper.text()).toContain('Something went wrong');
  });
});

describe('ScopeList', () => {
  it('renders collapsible panel for items with values', () => {
    const items = [{ name: 'read profile', values: { email: 'user@test.com' } }];
    const wrapper = mount(ScopeList, {
      props: { items, idPrefix: 'oauth2Scope' },
      global: { plugins: [createTestI18n()] },
    });

    const panel = wrapper.find('.panel-info');
    expect(panel.exists()).toBe(true);
    expect(panel.find('.panel-heading').text()).toContain('read profile');
  });

  it('renders static panel for items without values', () => {
    const items = [{ name: 'basic access' }];
    const wrapper = mount(ScopeList, {
      props: { items, idPrefix: 'oauth2Scope' },
      global: { plugins: [createTestI18n()] },
    });

    const panel = wrapper.find('.panel-default');
    expect(panel.exists()).toBe(true);
    expect(panel.find('.panel-heading').text()).toContain('basic access');
  });

  it('toggles panel on click', async () => {
    const items = [{ name: 'scope', values: 'detail' }];
    const wrapper = mount(ScopeList, {
      props: { items, idPrefix: 'oauth2Scope' },
      global: { plugins: [createTestI18n()] },
    });

    const heading = wrapper.find('.panel-heading');
    const panelBody = wrapper.find('.panel-body');

    // Initially collapsed — panel-body should not be rendered in DOM
    expect(panelBody.exists()).toBe(false);

    await heading.trigger('click');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('.panel-body').exists()).toBe(true);

    await heading.trigger('click');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('.panel-body').exists()).toBe(false);
  });
});

describe('AuthorizeForm', () => {
  it('renders form with correct method and autocomplete', () => {
    const pageData = createAuthorizeTestWrapper();
    const wrapper = mount(AuthorizeForm, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    const form = wrapper.find('form');
    expect(form.exists()).toBe(true);
    expect(form.attributes('method')).toBe('post');
    expect(form.attributes('autocomplete')).toBe('off');
  });

  it('renders deny and allow buttons', () => {
    const pageData = createAuthorizeTestWrapper();
    const wrapper = mount(AuthorizeForm, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    const denyBtn = wrapper.find('button[value="deny"]');
    const allowBtn = wrapper.find('button[value="allow"]');
    expect(denyBtn.exists()).toBe(true);
    expect(allowBtn.exists()).toBe(true);
    expect(denyBtn.text()).toBe('Deny');
    expect(allowBtn.text()).toBe('Allow');
  });

  it('renders hidden fields for required oauth2 data', () => {
    const pageData = createAuthorizeTestWrapper();
    const wrapper = mount(AuthorizeForm, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.find('input[name="response_type"]').attributes('value')).toBe('code');
    expect(wrapper.find('input[name="client_id"]').attributes('value')).toBe('test-client');
    expect(wrapper.find('input[name="csrf"]').attributes('value')).toBe('mock-csrf');
  });
});

describe('AuthorizeApp', () => {
  it('renders ErrorDisplay when pageData.error is set', () => {
    const pageData = createAuthorizeTestWrapper({
      error: { message: 'Access denied' },
    });
    const wrapper = mount(AuthorizeApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.findComponent(ErrorDisplay).exists()).toBe(true);
    expect(wrapper.findComponent(AuthorizeForm).exists()).toBe(false);
  });

  it('renders AuthorizeForm when no error', () => {
    const pageData = createAuthorizeTestWrapper();
    const wrapper = mount(AuthorizeApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.findComponent(AuthorizeForm).exists()).toBe(true);
    expect(wrapper.findComponent(ErrorDisplay).exists()).toBe(false);
  });

  it('renders login-base structure with logo holder and content div', () => {
    const pageData = createAuthorizeTestWrapper();
    const wrapper = mount(AuthorizeApp, {
      props: { pageData },
      global: { plugins: [createTestI18n()] },
    });

    expect(wrapper.find('#login-base').exists()).toBe(true);
    expect(wrapper.find('#loginBaseLogo').exists()).toBe(true);
    expect(wrapper.find('#content').exists()).toBe(true);
    expect(wrapper.find('#footer').exists()).toBe(true);
  });
});
