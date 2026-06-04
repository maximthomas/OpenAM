import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { flushPromises } from '@vue/test-utils';
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
        forgotPassword: false,
        forgotUsername: false,
        selfRegistration: false,
        socialImplementations: [],
      },
    },
  },
}));

describe('useLogin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const { reset } = useLogin();
    reset();
    document.cookie.split(';').forEach((c) => {
      document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/');
    });
  });

  describe('reset', () => {
    it('resets state to initial values', () => {
      const { reset, state } = useLogin();
      reset();
      expect(state.phase).toBe('initializing');
      expect(state.requirements).toBeNull();
      expect(state.error).toBeNull();
      expect(state.stage).toBeNull();
      expect(state.currentStage).toBe(0);
      expect(state.gotoUrl).toBeNull();
      expect(state.tokenId).toBeNull();
    });
  });

  describe('startLogin', () => {
    it('sets phase to form when auth returns callbacks', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        stage: 'DataStore1',
        callbacks: [
          { type: 'TextInputCallback', output: [{ name: 'prompt', value: 'User Name' }], input: [{ name: 'input', value: '' }] },
          { type: 'PasswordCallback', output: [{ name: 'prompt', value: 'Password' }], input: [{ name: 'password', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }, { name: 'defaultOption', value: 0 }], input: [{ name: 'loginButton', value: 0 }] },
        ],
      });

      const { startLogin, state } = useLogin();
      await startLogin('root');

      expect(state.phase).toBe('form');
      expect(state.requirements).not.toBeNull();
      expect(state.stage).toBe('DataStore1');
    });

    it('sets phase to success when auth returns tokenId', async () => {
      mockBegin.mockResolvedValue({
        tokenId: 'session-123',
        realm: '/',
      });

      const { startLogin, state } = useLogin();
      await startLogin('root');

      expect(state.phase).toBe('success');
      expect(state.tokenId).toBe('session-123');
    });

    it('sets phase to error on failure', async () => {
      mockBegin.mockRejectedValue(new Error('Network error'));

      const { startLogin, state } = useLogin();
      await startLogin('root');

      expect(state.phase).toBe('error');
      expect(state.error).toBe('Network error');
    });

    it('uses authId cookie to resume auth', async () => {
      document.cookie = 'authId=existing-auth-id;path=/';
      mockSubmitRequirements.mockResolvedValue({
        authId: 'new-auth-id',
        stage: 'DataStore1',
        callbacks: [{ type: 'PasswordCallback', output: [], input: [{ name: 'password', value: '' }] }],
      });

      const { startLogin, state } = useLogin();
      await startLogin('root');

      expect(mockSubmitRequirements).toHaveBeenCalledWith(
        { authId: 'existing-auth-id' },
        'root',
        undefined,
      );
      expect(state.phase).toBe('form');
    });

    it('removes authId cookie after resume', async () => {
      document.cookie = 'authId=existing-auth-id;path=/';
      mockSubmitRequirements.mockResolvedValue({
        authId: 'new-auth-id',
        callbacks: [{ type: 'PasswordCallback', output: [], input: [{ name: 'password', value: '' }] }],
      });

      const { startLogin } = useLogin();
      await startLogin('root');

      expect(document.cookie).not.toContain('authId=');
    });

    it('handles RedirectCallback by setting redirecting phase', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        callbacks: [
          {
            type: 'RedirectCallback',
            output: [
              { name: 'redirectUrl', value: 'https://example.com/sso' },
              { name: 'trackingCookie', value: true },
              { name: 'waitForReturn', value: false },
              { name: 'waitTimeout', value: 0 },
            ],
          },
        ],
      });

      const replaceSpy = vi.spyOn(window.location, 'replace').mockImplementation(() => {});

      const { startLogin, state } = useLogin();
      await startLogin('root');

      expect(state.phase).toBe('redirecting');
      replaceSpy.mockRestore();
    });

    it('handles PollingWaitCallback by setting polling phase', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        callbacks: [
          {
            type: 'PollingWaitCallback',
            output: [
              { name: 'waitTime', value: 5000 },
              { name: 'message', value: 'Waiting...' },
            ],
          },
        ],
      });

      const { startLogin, state } = useLogin();
      await startLogin('root');

      expect(state.phase).toBe('polling');
    });

    it('appends synthetic ConfirmationCallback when none exists', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        callbacks: [
          { type: 'TextInputCallback', output: [{ name: 'prompt', value: 'User Name' }], input: [{ name: 'input', value: '' }] },
        ],
      });

      const { startLogin, state } = useLogin();
      await startLogin('root');

      const hasConfirmation = state.requirements?.callbacks?.some(
        (cb) => cb.type === 'ConfirmationCallback',
      );
      expect(hasConfirmation).toBe(true);
    });

    it('does not append synthetic ConfirmationCallback when one exists', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        callbacks: [
          { type: 'TextInputCallback', output: [], input: [{ name: 'input', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['OK'] }], input: [{ name: 'button', value: 0 }] },
        ],
      });

      const { startLogin, state } = useLogin();
      await startLogin('root');

      const confirmationCount = state.requirements?.callbacks?.filter(
        (cb) => cb.type === 'ConfirmationCallback',
      ).length;
      expect(confirmationCount).toBe(1);
    });

    it('converts authlevel param to authIndexType=level', async () => {
      mockBegin.mockResolvedValue({ tokenId: 'token' });

      const { startLogin } = useLogin();
      await startLogin('root', { authlevel: '1' });

      expect(mockBegin).toHaveBeenCalledWith('root', { authlevel: '1' });
    });
  });

  describe('submitForm', () => {
    it('submits form data and transitions to form on next stage', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        callbacks: [
          { type: 'TextInputCallback', output: [], input: [{ name: 'input', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }], input: [{ name: 'button', value: 0 }] },
        ],
      });

      const { startLogin, submitForm, state } = useLogin();
      await startLogin('root');

      mockSubmitRequirements.mockResolvedValue({
        authId: 'auth-456',
        callbacks: [
          { type: 'PasswordCallback', output: [], input: [{ name: 'password', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Next'] }], input: [{ name: 'button', value: 0 }] },
        ],
      });

      await submitForm({ callback_0: 'user', callback_1: 0 });

      expect(state.phase).toBe('form');
      expect(state.requirements?.callbacks).toHaveLength(2);
    });

    it('sets phase to success when form submission returns tokenId', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        callbacks: [
          { type: 'PasswordCallback', output: [], input: [{ name: 'password', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }], input: [{ name: 'button', value: 0 }] },
        ],
      });

      const { startLogin, submitForm, state } = useLogin();
      await startLogin('root');

      mockSubmitRequirements.mockResolvedValue({
        tokenId: 'session-456',
        realm: '/',
      });

      mockValidateGoto.mockResolvedValue({ valid: false });

      await submitForm({ callback_0: 'password', callback_1: 0 });

      expect(state.phase).toBe('success');
      expect(state.tokenId).toBe('session-456');
    });

    it('sets error and redirects on stage > 1 failure', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        stage: 'DataStore1',
        callbacks: [
          { type: 'TextInputCallback', output: [], input: [{ name: 'input', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }], input: [{ name: 'button', value: 0 }] },
        ],
      });

      const { startLogin, submitForm, state } = useLogin();
      await startLogin('root');

      expect(state.currentStage).toBe(1);

      mockSubmitRequirements.mockResolvedValue({
        authId: 'auth-456',
        stage: 'DataStore1',
        callbacks: [
          { type: 'PasswordCallback', output: [], input: [{ name: 'password', value: '' }] },
          { type: 'ConfirmationCallback', output: [{ name: 'options', value: ['Login'] }], input: [{ name: 'button', value: 0 }] },
        ],
      });

      await submitForm({ callback_0: 'user', callback_1: 0 });
      expect(state.currentStage).toBe(2);

      mockSubmitRequirements.mockRejectedValue(new Error('Invalid credentials'));

      await submitForm({ callback_0: 'wrong', callback_1: 0 });

      expect(state.phase).toBe('error');
      expect(state.error).toBe('Invalid credentials');
    });

    it('does nothing when requirements is null', async () => {
      const { submitForm, state } = useLogin();
      await submitForm({});
      expect(state.phase).toBe('initializing');
    });
  });

  describe('isUserNamePasswordStage', () => {
    it('returns true for DataStore1 stage', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        stage: 'DataStore1',
        callbacks: [{ type: 'PasswordCallback', output: [], input: [] }],
      });

      const { startLogin, isUserNamePasswordStage } = useLogin();
      await startLogin('root');

      expect(isUserNamePasswordStage()).toBe(true);
    });

    it('returns false for unknown stage', async () => {
      mockBegin.mockResolvedValue({
        authId: 'auth-123',
        stage: 'CustomStage',
        callbacks: [{ type: 'PasswordCallback', output: [], input: [] }],
      });

      const { startLogin, isUserNamePasswordStage } = useLogin();
      await startLogin('root');

      expect(isUserNamePasswordStage()).toBe(false);
    });

    it('returns false when stage is null', () => {
      const { isUserNamePasswordStage } = useLogin();
      expect(isUserNamePasswordStage()).toBe(false);
    });
  });

  describe('cookie management', () => {
    it('getLoginRememberCookie returns saved username', () => {
      document.cookie = 'login=testuser;path=/';
      const { getLoginRememberCookie } = useLogin();
      expect(getLoginRememberCookie()).toBe('testuser');
    });

    it('setLoginRememberCookie sets cookie with 20 day expiry', () => {
      const { setLoginRememberCookie } = useLogin();
      setLoginRememberCookie('newuser');
      expect(document.cookie).toContain('login=newuser');
    });

    it('removeLoginRememberCookie removes cookie', () => {
      document.cookie = 'login=testuser;path=/';
      const { removeLoginRememberCookie } = useLogin();
      removeLoginRememberCookie();
      expect(document.cookie).not.toContain('login=');
    });

    it('removeAuthIdCookie removes authId cookie', () => {
      document.cookie = 'authId=some-id;path=/';
      const { removeAuthIdCookie } = useLogin();
      removeAuthIdCookie();
      expect(document.cookie).not.toContain('authId=');
    });
  });
});
