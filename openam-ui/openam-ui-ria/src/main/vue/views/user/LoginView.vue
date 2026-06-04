<template>
  <div id="login-base">
    <LoginHeader />
    <div class="container">

      <!-- Initializing -->
      <div v-if="phase === 'initializing'" class="text-center">
        <i class="fa fa-spinner fa-spin fa-3x text-primary" />
      </div>

      <!-- Error (stage > 1) -->
      <div v-else-if="phase === 'error'" class="text-center">
        <div class="page-header">
          <h1>{{ $t('openam.authentication.unavailable') }}</h1>
        </div>
        <p class="text-danger">{{ error }}</p>
        <a :href="loginHref" @click.prevent="returnToLogin">
          {{ $t('common.user.returnToLoginPage') }}
        </a>
      </div>

      <!-- Form -->
      <form
        v-else-if="phase === 'form' || phase === 'submitting'"
        class="form login col-sm-6 col-sm-offset-3"
        autocomplete="off"
        @submit.prevent="handleSubmit"
      >
        <!-- Inline error (first-stage failures) -->
        <div v-if="error" class="alert alert-danger" role="alert">
          {{ error }}
        </div>

        <fieldset class="row">
          <!-- Remember login checkbox -->
          <template v-if="isUserNamePasswordStage && showRememberLogin">
            <div class="form-group">
              <label>
                <input
                  v-model="rememberLogin"
                  type="checkbox"
                  name="loginRemember"
                />
                {{ $t('common.user.rememberLogin') || 'Remember login' }}
              </label>
            </div>
          </template>

          <!-- Callbacks -->
          <LoginCallback
            v-for="(cb, index) in visibleCallbacks"
            :key="index"
            :callback="cb"
            :index="getOriginalIndex(index)"
            v-model="formData[`callback_${getOriginalIndex(index)}`]"
            @submit="handleCallbackSubmit"
          />
        </fieldset>

        <!-- Self-service links -->
        <div class="form-group text-center">
          <template v-if="config.globalData.auth.forgotPassword === true">
            <router-link :to="{ name: 'passwordReset' }" class="login-link">
              {{ $t('common.user.forgotPassword') || 'Forgot password?' }}
            </router-link>
            <span v-if="config.globalData.auth.forgotUsername === true"> | </span>
          </template>
          <template v-if="config.globalData.auth.forgotUsername === true">
            <router-link :to="{ name: 'forgotUsername' }" class="login-link">
              {{ $t('common.user.forgotUsername') || 'Forgot username?' }}
            </router-link>
          </template>
          <template v-if="config.globalData.auth.selfRegistration === true">
            <br />
            <router-link :to="{ name: 'selfRegistration' }" class="login-link">
              {{ $t('common.user.register') || 'Register' }}
            </router-link>
          </template>
        </div>

        <!-- Social login -->
        <div
          v-if="isUserNamePasswordStage && !useAuthState.isAuthenticated.value && socialImplementations.length > 0"
          class="form-group text-center social-login"
        >
          <p>{{ $t('common.user.socialLogin') || 'Or sign in with:' }}</p>
          <a
            v-for="(social, idx) in socialImplementations"
            :key="idx"
            :href="social.oauth.authorizationEndpoint"
            class="icon-social-login"
          >
            <img v-if="social.icon" :src="social.icon" :alt="social.displayName" />
            <span v-else>{{ social.displayName }}</span>
          </a>
        </div>
      </form>

      <!-- Polling -->
      <div v-else-if="phase === 'polling'" class="text-center">
        <div class="panel panel-default">
          <div class="panel-body">
            <h4 class="awaiting-response">
              <i class="fa fa-circle-o-notch fa-spin text-primary" />
              {{ $t('templates.user.LoginTemplate.waitingForResponse') || 'Waiting for response...' }}
            </h4>
          </div>
        </div>
      </div>

      <!-- Redirecting -->
      <div v-else-if="phase === 'redirecting'" class="text-center">
        <i class="fa fa-spinner fa-spin fa-3x text-primary" />
        <p>{{ $t('common.user.redirecting') || 'Redirecting...' }}</p>
      </div>

    </div>
    <LoginFooter />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick } from 'vue';
import { useRoute } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { useLogin } from '@/composables/useLogin';
import { useAuth } from '@/composables/useAuth';
import { config } from '@/services/config';
import LoginHeader from '@/components/common/LoginHeader.vue';
import LoginFooter from '@/components/common/LoginFooter.vue';
import LoginCallback from '@/components/auth/LoginCallback.vue';
import type { LoginCallback as LoginCallbackType } from '@/types/user';

const { t } = useI18n();
const route = useRoute();
const login = useLogin();
const useAuthState = useAuth();

const props = withDefaults(defineProps<{
  backgroundLogin?: boolean;
}>(), {
  backgroundLogin: false,
});

const emit = defineEmits<{
  success: [];
}>();

const formData = ref<Record<string, unknown>>({});
const rememberLogin = ref(false);
const hasSubmittedOnce = ref(false);

const phase = computed(() => login.state.phase);
const error = computed(() => login.state.error);
const requirements = computed(() => login.state.requirements);
const stage = computed(() => login.state.stage);

const socialImplementations = computed(() => config.globalData.auth.socialImplementations || []);

const isUserNamePasswordStage = computed(() => login.isUserNamePasswordStage());

const showRememberLogin = computed(() => {
  if (!requirements.value?.callbacks) return false;
  const hasConfirmation = requirements.value.callbacks.some((cb) => cb.type === 'ConfirmationCallback');
  return isUserNamePasswordStage.value && hasConfirmation;
});

const hiddenCallbackTypes = ['RedirectCallback', 'PollingWaitCallback', 'HiddenValueCallback'];

const visibleCallbacks = computed(() => {
  if (!requirements.value?.callbacks) return [];
  return requirements.value.callbacks.filter((cb) => !hiddenCallbackTypes.includes(cb.type));
});

function getOriginalIndex(visibleIndex: number): number {
  if (!requirements.value?.callbacks) return visibleIndex;
  let visibleCount = 0;
  for (let i = 0; i < requirements.value.callbacks.length; i++) {
    if (!hiddenCallbackTypes.includes(requirements.value.callbacks[i].type)) {
      if (visibleCount === visibleIndex) return i;
      visibleCount++;
    }
  }
  return visibleIndex;
}

const loginHref = computed(() => '#/login');

function returnToLogin(): void {
  window.location.replace(loginHref.value);
}

function initFormData(): void {
  if (!requirements.value?.callbacks) return;
  const data: Record<string, unknown> = {};
  requirements.value.callbacks.forEach((cb, index) => {
    data[`callback_${index}`] = cb.input?.[0]?.value ?? '';
  });
  formData.value = data;
}

function prefillRememberLogin(): void {
  if (!isUserNamePasswordStage.value) return;
  const savedLogin = login.getLoginRememberCookie();
  if (savedLogin) {
    const firstTextIndex = requirements.value?.callbacks?.findIndex(
      (cb) => cb.type === 'TextInputCallback' || cb.type === 'PasswordCallback',
    );
    if (firstTextIndex !== undefined && firstTextIndex >= 0) {
      formData.value[`callback_${firstTextIndex}`] = savedLogin;
      rememberLogin.value = true;
    }
  }
}

function focusFirstInput(): void {
  nextTick(() => {
    const firstInput = document.querySelector<HTMLInputElement>(
      'input:not([type="radio"]):not([type="checkbox"]):not([type="submit"]):not([type="button"])',
    );
    if (firstInput) {
      firstInput.focus();
    }
  });
}

function handleSubmit(): void {
  hasSubmittedOnce.value = true;

  if (rememberLogin.value) {
    const firstTextIndex = requirements.value?.callbacks?.findIndex(
      (cb) => cb.type === 'TextInputCallback',
    );
    if (firstTextIndex !== undefined && firstTextIndex >= 0) {
      const username = String(formData.value[`callback_${firstTextIndex}`] || '');
      if (username) {
        login.setLoginRememberCookie(username);
      }
    }
  } else if (requirements.value?.callbacks?.some((cb) => cb.type === 'TextInputCallback')) {
    login.removeLoginRememberCookie();
  }

  login.submitForm(formData.value);
}

function handleCallbackSubmit(_index: number): void {
  handleSubmit();
}

watch(phase, (newPhase) => {
  if (newPhase === 'form') {
    initFormData();
    prefillRememberLogin();
    focusFirstInput();
  }
  if (newPhase === 'success') {
    if (props.backgroundLogin) {
      emit('success');
      return;
    }
    const gotoUrl = login.state.gotoUrl;
    if (gotoUrl && !['', '#/', '#', '/#'].includes(gotoUrl)) {
      window.location.href = gotoUrl;
    } else {
      useAuthState.setUser({
        username: '',
        realm: login.state.realm,
        roles: [],
      });
      window.location.href = '#/';
      window.location.reload();
    }
  }
  if (newPhase === 'error' && login.state.currentStage > 1) {
    const params = new URLSearchParams(window.location.hash.split('?')[1]);
    const paramStr = params.toString();
    window.location.href = `#/failedLogin${paramStr ? '?' + paramStr : ''}`;
    window.location.reload();
  }
});

onMounted(() => {
  const realm = (route.params.realm as string) || '/';
  const params: Record<string, string> = {};

  if (route.query.service) params.service = route.query.service as string;
  if (route.query.goto) params.goto = route.query.goto as string;
  if (route.query.ForceAuth) params.ForceAuth = route.query.ForceAuth as string;
  if (route.query.authIndexType) params.authIndexType = route.query.authIndexType as string;
  if (route.query.authIndexValue) params.authIndexValue = route.query.authIndexValue as string;

  login.startLogin(realm, Object.keys(params).length > 0 ? params : undefined);
});
</script>
