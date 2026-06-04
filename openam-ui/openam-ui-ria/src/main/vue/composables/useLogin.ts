import { reactive, readonly } from 'vue';
import { authNApi } from '@/services/authN';
import { config } from '@/services/config';
import type { AuthRequirements, LoginCallback } from '@/types/user';

export type LoginPhase = 'initializing' | 'form' | 'submitting' | 'polling' | 'redirecting' | 'error' | 'success';

interface LoginState {
  phase: LoginPhase;
  requirements: AuthRequirements | null;
  error: string | null;
  stage: string | null;
  currentStage: number;
  gotoUrl: string | null;
  tokenId: string | null;
  realm: string;
}

const USERNAME_PASSWORD_STAGES = ['DataStore1', 'AD1', 'JDBC1', 'LDAP1', 'Membership1', 'RADIUS1'];

function getCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

function setCookie(name: string, value: string, days: number): void {
  const expire = new Date();
  expire.setDate(expire.getDate() + days);
  document.cookie = `${name}=${encodeURIComponent(value)};expires=${expire.toUTCString()};path=/`;
}

function removeCookie(name: string): void {
  document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
}

export function useLogin() {
  const state = reactive<LoginState>({
    phase: 'initializing',
    requirements: null,
    error: null,
    stage: null,
    currentStage: 0,
    gotoUrl: null,
    tokenId: null,
    realm: '/',
  });

  let pollingTimer: ReturnType<typeof setTimeout> | null = null;
  let redirectHandled = false;

  function reset(): void {
    if (pollingTimer) {
      clearTimeout(pollingTimer);
      pollingTimer = null;
    }
    redirectHandled = false;
    state.phase = 'initializing';
    state.requirements = null;
    state.error = null;
    state.stage = null;
    state.currentStage = 0;
    state.gotoUrl = null;
    state.tokenId = null;
    state.realm = '/';
  }

  function removeAuthIdCookie(): void {
    removeCookie('authId');
  }

  function handleRequirements(reqs: AuthRequirements): void {
    if (reqs.authId) {
      state.currentStage++;
      config.globalData.auth.currentStage = state.currentStage;

      const hasTrackingCookie = reqs.callbacks?.some(
        (cb) => cb.type === 'RedirectCallback' &&
          cb.output?.some((o) => o.name === 'trackingCookie' && o.value === true),
      );

      if (hasTrackingCookie && !getCookie('authId')) {
        setCookie('authId', reqs.authId, 1);
      }
    } else if (reqs.tokenId) {
      state.tokenId = reqs.tokenId;
    }
  }

  async function resolveGotoUrl(successUrl?: string): Promise<void> {
    const gotoParam = new URLSearchParams(window.location.hash.split('?')[1]).get('goto');

    if (gotoParam) {
      try {
        const result = await authNApi.validateGoto(gotoParam);
        let goto = result.valid ? (result as unknown as { successURL: string }).successURL : successUrl;
        if (goto && goto.startsWith('/') && !goto.startsWith(`/${config.globalData.auth.subRealm || ''}`)) {
          goto = `/${config.globalData.auth.subRealm || ''}${goto}`;
        }
        state.gotoUrl = goto || null;
      } catch {
        state.gotoUrl = null;
      }
    } else if (successUrl && successUrl !== '/openam/console') {
      state.gotoUrl = successUrl;
    }
  }

  function handleRedirectCallback(callbacks: LoginCallback[]): boolean {
    const redirectCb = callbacks.find((cb) => cb.type === 'RedirectCallback') as import('@/types/user').RedirectCallback | undefined;
    if (!redirectCb) return false;

    const redirectUrl = redirectCb.output.find((o) => o.name === 'redirectUrl')?.value as string;
    const trackingCookie = redirectCb.output.find((o) => o.name === 'trackingCookie')?.value as boolean;

    if (trackingCookie && state.requirements?.authId) {
      setCookie('authId', state.requirements.authId, 1);
    }

    if (!redirectUrl) return false;

    const redirectData = redirectCb.output.find((o) => o.name === 'redirectData');
    if (redirectData?.value) {
      const form = document.createElement('form');
      form.action = redirectUrl;
      form.method = 'POST';
      const data = redirectData.value as Record<string, string>;
      for (const [key, val] of Object.entries(data)) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = val;
        form.appendChild(input);
      }
      document.body.appendChild(form);
      form.submit();
    } else {
      window.location.replace(redirectUrl);
    }
    return true;
  }

  function handlePollingWait(callbacks: LoginCallback[]): void {
    const pollingCb = callbacks.find((cb) => cb.type === 'PollingWaitCallback') as import('@/types/user').PollingWaitCallback | undefined;
    if (!pollingCb) return;

    const waitTime = pollingCb.output.find((o) => o.name === 'waitTime')?.value as number;
    if (!waitTime) return;

    state.phase = 'polling';
    pollingTimer = setTimeout(() => {
      if (state.phase === 'polling' && state.requirements) {
        submitForm();
      }
    }, waitTime);
  }

  function addSyntheticConfirmation(reqs: AuthRequirements): AuthRequirements {
    if (!reqs.callbacks) return reqs;

    const hasConfirmation = reqs.callbacks.some((cb) => cb.type === 'ConfirmationCallback');
    const hasPolling = reqs.callbacks.some((cb) => cb.type === 'PollingWaitCallback');

    if (!hasConfirmation && !hasPolling) {
      const synthetic: LoginCallback = {
        type: 'ConfirmationCallback',
        output: [
          { name: 'prompt', value: '' },
          { name: 'options', value: ['Login'] },
          { name: 'optionType', value: 0 },
          { name: 'defaultOption', value: 0 },
          { name: 'value', value: false },
        ],
        input: [{ name: 'loginButton', value: 0 }],
      };
      return { ...reqs, callbacks: [...reqs.callbacks, synthetic] };
    }
    return reqs;
  }

  async function startLogin(realm: string, params?: Record<string, string>): Promise<void> {
    reset();
    state.realm = realm;
    state.phase = 'initializing';

    try {
      const authIdCookie = getCookie('authId');

      let reqs: AuthRequirements;
      if (authIdCookie) {
        reqs = await authNApi.submitRequirements({ authId: authIdCookie }, realm, params);
        removeCookie('authId');
      } else {
        reqs = await authNApi.begin(realm, params);
      }

      handleRequirements(reqs);

      if (reqs.tokenId) {
        state.phase = 'success';
        return;
      }

      if (reqs.authId && reqs.callbacks) {
        if (handleRedirectCallback(reqs.callbacks)) {
          state.phase = 'redirecting';
          return;
        }

        if (reqs.callbacks.some((cb) => cb.type === 'PollingWaitCallback') &&
            !reqs.callbacks.some((cb) => cb.type !== 'PollingWaitCallback')) {
          handlePollingWait(reqs.callbacks);
          return;
        }

        state.requirements = addSyntheticConfirmation(reqs);
        state.stage = reqs.stage || null;

        if (reqs.stage) {
          config.globalData.auth.currentStage = state.currentStage;
        }

        state.phase = 'form';
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Login failed';
      state.error = message;
      state.phase = 'error';
    }
  }

  async function submitForm(formData?: Record<string, unknown>): Promise<void> {
    if (!state.requirements) return;

    state.phase = 'submitting';
    state.error = null;

    try {
      const populatedCallbacks = state.requirements.callbacks?.map((cb, index) => {
        if (!cb.input) return cb;
        const key = `callback_${index}`;
        const value = formData?.[key] ?? cb.input[0]?.value;
        return {
          ...cb,
          input: [{ ...cb.input[0], value }],
        };
      }) || [];

      const submitReqs: AuthRequirements = {
        ...state.requirements,
        callbacks: populatedCallbacks as LoginCallback[],
      };

      const result = await authNApi.submitRequirements(submitReqs, state.realm);

      handleRequirements(result);

      if (result.tokenId) {
        removeAuthIdCookie();
        await resolveGotoUrl(result.detail?.successUrl);
        state.phase = 'success';
        return;
      }

      if (result.authId && result.callbacks) {
        if (handleRedirectCallback(result.callbacks)) {
          state.phase = 'redirecting';
          return;
        }

        if (result.callbacks.some((cb) => cb.type === 'PollingWaitCallback') &&
            !result.callbacks.some((cb) => cb.type !== 'PollingWaitCallback')) {
          state.requirements = result;
          handlePollingWait(result.callbacks);
          return;
        }

        state.requirements = addSyntheticConfirmation(result);
        state.stage = result.stage || null;
        state.phase = 'form';
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Login failed';

      if (state.currentStage > 1) {
        state.error = message;
        state.phase = 'error';
        return;
      }

      state.error = message;
      state.phase = 'form';
    }
  }

  function isUserNamePasswordStage(): boolean {
    return state.stage ? USERNAME_PASSWORD_STAGES.includes(state.stage) : false;
  }

  function getLoginRememberCookie(): string {
    return getCookie('login');
  }

  function setLoginRememberCookie(username: string): void {
    setCookie('login', username, 20);
  }

  function removeLoginRememberCookie(): void {
    removeCookie('login');
  }

  return {
    state: readonly(state),
    reset,
    startLogin,
    submitForm,
    isUserNamePasswordStage,
    getLoginRememberCookie,
    setLoginRememberCookie,
    removeLoginRememberCookie,
    removeAuthIdCookie,
  };
}
