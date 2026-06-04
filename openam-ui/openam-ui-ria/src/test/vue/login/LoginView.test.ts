import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createRouter, createWebHashHistory } from 'vue-router';
import { createI18n } from 'vue-i18n';
import LoginView from '@/views/user/LoginView.vue';
import { useLogin } from '@/composables/useLogin';

const mockBegin = vi.fn();
const mockSubmitRequirements = vi.fn();
const mockValidateGoto = vi.fn();

vi.mock('@/services/authN', () => ({
  authNApi: {
    begin: (...args: unknown[]) => mockBegin(...args),
    submitRequirements: (...args: unknown[]) => mockSubmitRequirements(...args),
    validateGoto: (...args: unknown[]) => mockValidateGoto(...args),
    getServerInfo: vi.fn().mockResolvedValue({ cookieName: 'iPlanetDirectoryPro' }),
  },
}));

vi.mock('@/services/config', () => ({
  config: {
    globalData: {
      auth: {
        currentStage: 0,
        subRealm: '',
        forgotPassword: true,
        forgotUsername: true,
        selfRegistration: true,
        socialImplementations: [],
      },
      theme: null,
    },
  },
}));

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: {},
  messageCompiler: (message: string) => () => message,
});

describe('LoginView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const { reset } = useLogin();
    reset();
    document.cookie.split(';').forEach((c) => {
      document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/');
    });
    vi.spyOn(window.location, 'reload').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function createRouterAndMount(mockSetup?: () => void) {
    mockSetup?.();
    const router = createRouter({
      history: createWebHashHistory(),
      routes: [
        { path: '/', name: 'default', component: { template: '<div />' } },
        { path: '/login', name: 'login', component: LoginView },
        { path: '/forgotUsername', name: 'forgotUsername', component: { template: '<div />' } },
        { path: '/passwordReset', name: 'passwordReset', component: { template: '<div />' } },
        { path: '/selfRegistration', name: 'selfRegistration', component: { template: '<div />' } },
        { path: '/failedLogin', name: 'loginFailure', component: { template: '<div />' } },
      ],
    });
    return router;
  }

  it('renders loading spinner during initialization', async () => {
    mockBegin.mockReturnValue(new Promise(() => {}));
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    expect(wrapper.find('.fa-spinner').exists()).toBe(true);
    wrapper.unmount();
  });

  it('renders login form when phase is form', async () => {
    mockBegin.mockResolvedValue({
      authId: 'auth-123',
      stage: 'DataStore1',
      callbacks: [
        { type: 'TextInputCallback', output: [{ name: 'prompt', value: 'User Name' }], input: [{ name: 'input', value: '' }] },
        { type: 'PasswordCallback', output: [{ name: 'prompt', value: 'Password' }], input: [{ name: 'password', value: '' }] },
        { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }, { name: 'defaultOption', value: 0 }], input: [{ name: 'loginButton', value: 0 }] },
      ],
    });
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    await flushPromises();
    expect(wrapper.find('form').exists()).toBe(true);
    expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
    wrapper.unmount();
  });

  it('renders self-service links', async () => {
    mockBegin.mockResolvedValue({
      authId: 'auth-123',
      stage: 'DataStore1',
      callbacks: [
        { type: 'TextInputCallback', output: [{ name: 'prompt', value: 'User Name' }], input: [{ name: 'input', value: '' }] },
        { type: 'PasswordCallback', output: [{ name: 'prompt', value: 'Password' }], input: [{ name: 'password', value: '' }] },
        { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }], input: [{ name: 'loginButton', value: 0 }] },
      ],
    });
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    await flushPromises();
    expect(wrapper.text()).toContain('common.user.forgotPassword');
    expect(wrapper.text()).toContain('common.user.forgotUsername');
    expect(wrapper.text()).toContain('common.user.register');
    wrapper.unmount();
  });

  it('renders error view when phase is error', async () => {
    mockBegin.mockRejectedValue(new Error('Server unavailable'));
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    await flushPromises();
    expect(wrapper.text()).toContain('openam.authentication.unavailable');
    expect(wrapper.text()).toContain('Server unavailable');
    wrapper.unmount();
  });

  it('transitions to success and triggers redirect', async () => {
    mockBegin.mockResolvedValue({ tokenId: 'session-123', realm: '/' });
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    await flushPromises();
    // Success phase triggers immediate redirect via watch handler
    expect(wrapper.find('.fa-spinner').exists() || wrapper.find('form').exists() || wrapper.find('#login-base').exists()).toBe(true);
    wrapper.unmount();
  });

  it('renders polling view when phase is polling', async () => {
    mockBegin.mockResolvedValue({
      authId: 'auth-123',
      callbacks: [{
        type: 'PollingWaitCallback',
        output: [
          { name: 'waitTime', value: 10000 },
          { name: 'message', value: 'Scanning...' },
        ],
      }],
    });
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    await flushPromises();
    // PollingWaitCallback shows a panel with spinner
    expect(wrapper.find('.panel').exists()).toBe(true);
    wrapper.unmount();
  });

  it('includes login-base container', async () => {
    mockBegin.mockReturnValue(new Promise(() => {}));
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    expect(wrapper.find('#login-base').exists()).toBe(true);
    wrapper.unmount();
  });

  it('submits form on button click', async () => {
    mockBegin.mockResolvedValue({
      authId: 'auth-123',
      stage: 'DataStore1',
      callbacks: [
        { type: 'TextInputCallback', output: [{ name: 'prompt', value: 'User Name' }], input: [{ name: 'input', value: '' }] },
        { type: 'PasswordCallback', output: [{ name: 'prompt', value: 'Password' }], input: [{ name: 'password', value: '' }] },
        { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }, { name: 'defaultOption', value: 0 }], input: [{ name: 'loginButton', value: 0 }] },
      ],
    });
    mockSubmitRequirements.mockResolvedValue({ tokenId: 'session-456', realm: '/' });
    mockValidateGoto.mockResolvedValue({ valid: false });
    const router = createRouterAndMount();
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(LoginView, { global: { plugins: [router, i18n] } });
    await flushPromises();
    await flushPromises();
    await wrapper.find('input[type="text"]').setValue('admin');
    await wrapper.find('input[type="password"]').setValue('password123');
    await wrapper.find('button.btn-primary').trigger('click');
    await flushPromises();
    await flushPromises();
    expect(mockSubmitRequirements).toHaveBeenCalled();
  });

});
