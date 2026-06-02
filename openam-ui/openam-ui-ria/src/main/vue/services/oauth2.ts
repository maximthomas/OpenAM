import axios from 'axios';
import { Constants } from './constants';

function getCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

function computeBaseUrl(): string {
  const oauth2ContextPath = 'oauth2';
  const parts = Constants.context.split('/');
  const oauth2Index = parts.indexOf(oauth2ContextPath);

  if (oauth2Index === -1) {
    return '';
  }

  const uriContext = parts.slice(0, oauth2Index).join('/');
  return uriContext ? `/${uriContext}/json` : '/json';
}

export async function getUserSessionId(): Promise<string> {
  const baseUrl = computeBaseUrl();
  if (!baseUrl) {
    return '';
  }

  try {
    const response = await axios.get<{ cookieName: string }>(
      `${baseUrl}/serverinfo/*`,
      {
        headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.1' },
        withCredentials: true,
      },
    );
    return getCookie(response.data.cookieName);
  } catch {
    return '';
  }
}
