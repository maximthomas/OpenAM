import { RestClient } from './api';
import { Constants } from './constants';

const API_VERSION = 'protocol=1.0,resource=1.1';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

export interface SessionInfo {
  tokenId: string;
  uid: string;
  realm: string;
  username: string;
  sessionHandle?: string;
  maxIdleTime?: number;
  maxTime?: number;
  timeLeft?: number;
  idleTime?: number;
  [key: string]: unknown;
}

/**
 * Session REST operations.
 *
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const sessionApi = {
  /**
   * Get current session information.
   * Uses the getSessionInfo action on the sessions endpoint.
   */
  getSessionInfo(): Promise<SessionInfo> {
    const client = new RestClient(buildBaseUrl());
    return client.post<SessionInfo>(
      '/sessions?_action=getSessionInfo',
      {},
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Destroy a session by its token ID.
   */
  destroySession(tokenId: string): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `/sessions/${encodeURIComponent(tokenId)}?_action=destroy`,
      {},
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Get session properties.
   */
  getSessionProperties(tokenId: string): Promise<Record<string, unknown>> {
    const client = new RestClient(buildBaseUrl());
    return client.get<Record<string, unknown>>(
      `/sessions/${encodeURIComponent(tokenId)}/properties`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },
};
