import { createApp } from 'vue';
import axios from 'axios';
import App from './App.vue';
import router from './router';
import i18n, { configureI18n } from './i18n';
import { Constants } from './services/constants';
import { config } from './services/config';
import { getTheme } from './services/theme';
import { themeConfiguration } from './services/themeConfiguration';
import { useAuth } from './composables/useAuth';

interface ServerInfoResponse {
  cookieName: string;
}

interface SessionInfoResponse {
  username: string;
  realm: string;
  sessionHandle?: string;
  usernameId?: string;
}

interface UserProfileResponse {
  username: string;
  realm: string;
  roles?: string[];
  uiroles?: string[];
}

function getCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

function computeServerBaseUrl(): string {
  const parts = Constants.context.split('/');
  const jsonIndex = parts.indexOf('json');
  if (jsonIndex !== -1) {
    return parts.slice(0, jsonIndex).join('/') + '/json';
  }
  return parts.length > 0 ? '/' + parts.join('/') + '/json' : '/json';
}

async function fetchServerInfo(): Promise<string> {
  const baseUrl = computeServerBaseUrl();
  const response = await axios.get<ServerInfoResponse>(
    `${baseUrl}/serverinfo/*`,
    {
      headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.1' },
      withCredentials: true,
    },
  );
  return response.data.cookieName;
}

async function validateSession(cookieName: string): Promise<SessionInfoResponse | null> {
  const token = getCookie(cookieName);
  if (!token) {
    return null;
  }

  const baseUrl = computeServerBaseUrl();
  try {
    const response = await axios.post<SessionInfoResponse>(
      `${baseUrl}/sessions?_action=getSessionInfo&tokenId=${encodeURIComponent(token)}`,
      {},
      {
        headers: {
          'Accept-API-Version': 'protocol=1.0,resource=2.0',
          'X-Requested-With': 'XMLHttpRequest',
        },
        withCredentials: true,
      },
    );
    return response.data;
  } catch {
    return null;
  }
}

async function fetchUserProfile(username: string, realm: string): Promise<UserProfileResponse | null> {
  const baseUrl = computeServerBaseUrl();
  try {
    const response = await axios.post<UserProfileResponse>(
      `${baseUrl}/users/${encodeURIComponent(username)}?_action=read`,
      {},
      {
        headers: {
          'Accept-API-Version': 'protocol=1.0,resource=2.0',
          'X-Requested-With': 'XMLHttpRequest',
        },
        withCredentials: true,
      },
    );
    return { ...response.data, username, realm };
  } catch {
    return null;
  }
}

async function bootstrap(): Promise<void> {
  const auth = useAuth();

  try {
    // 1. Fetch server info to get cookie name
    const cookieName = await fetchServerInfo();

    // 2. Validate session
    const sessionInfo = await validateSession(cookieName);

    if (sessionInfo) {
      // 3. Fetch user profile
      const userProfile = await fetchUserProfile(sessionInfo.username, sessionInfo.realm);

      if (userProfile) {
        auth.setUser({
          username: userProfile.username,
          realm: userProfile.realm,
          roles: userProfile.uiroles ?? userProfile.roles ?? [],
        });
      } else {
        // Session valid but profile fetch failed — use session data
        auth.setUser({
          username: sessionInfo.username,
          realm: sessionInfo.realm,
          roles: [],
        });
      }
    }
  } catch {
    // Server unreachable or error — proceed unauthenticated
  }

  auth.setInitialized(true);

  // 4. Configure i18n
  await configureI18n('/openam/XUI', 'common', { locale: 'en' });

  // 5. Apply theme
  getTheme(themeConfiguration, '/', true);

  // 6. Mount app
  const app = createApp(App);
  app.use(router);
  app.use(i18n);
  app.mount('#app');
}

bootstrap();
