import { RestClient } from './api';
import { Constants } from './constants';
import type { OAuthToken } from '@/types/user';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/frrest/oauth2/token`;
}

/**
 * OAuth2 token REST operations.
 *
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const tokenApi = {
  /**
   * Get all OAuth2 tokens for the current user.
   */
  getAllTokens(): Promise<OAuthToken[]> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ result: OAuthToken[] }>(
      '/?_queryid=*',
      { headers: { 'Cache-Control': 'no-cache' } },
    ).then((response) => response.result);
  },

  /**
   * Delete a token by its ID.
   */
  deleteToken(id: string): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.delete<void>(
      `/${encodeURIComponent(id)}`,
      { headers: { 'Cache-Control': 'no-cache' } },
    );
  },

  /**
   * Get a token by its ID.
   */
  getTokenById(id: string): Promise<OAuthToken> {
    const client = new RestClient(buildBaseUrl());
    return client.get<OAuthToken>(
      `/${encodeURIComponent(id)}`,
      { headers: { 'Cache-Control': 'no-cache' } },
    );
  },
};
