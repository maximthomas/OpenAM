import axios from 'axios';
import { Constants } from './constants';
import { useAuth } from '@/composables/useAuth';

function getServerBaseUrl(): string {
  const parts = Constants.context.split('/');
  const jsonIndex = parts.indexOf('json');
  if (jsonIndex !== -1) {
    return parts.slice(0, jsonIndex).join('/') + '/json';
  }
  return parts.length > 0 ? '/' + parts.join('/') + '/json' : '/json';
}

export async function logout(): Promise<void> {
  const { reset } = useAuth();
  const baseUrl = getServerBaseUrl();

  try {
    await axios.post(
      `${baseUrl}/realms/root/auth/logout`,
      {},
      {
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
        },
        withCredentials: true,
      },
    );
  } catch {
    // Best-effort — proceed with client-side cleanup even if server call fails
  }

  reset();
  window.location.href = '#/login';
  window.location.reload();
}
