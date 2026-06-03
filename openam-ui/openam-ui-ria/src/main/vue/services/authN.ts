import { RestClient } from './api';
import { Constants } from './constants';
import type { AuthRequirements } from '@/types/user';

const API_VERSION = 'protocol=1.0,resource=2.1';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

/**
 * Authentication REST operations.
 *
 * Handles the authenticate endpoint flow: begin → submit → handle → next stage.
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const authNApi = {
  /**
   * Begin a new authentication process.
   * @param realm - The realm path (e.g., 'root', 'b2c/clients')
   * @param params - Additional URL parameters (authIndexType, authIndexValue, etc.)
   */
  begin(
    realm: string,
    params?: Record<string, string>,
  ): Promise<AuthRequirements> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? `/${realm}` : '';
    const queryString = params
      ? '?' + new URLSearchParams(params).toString()
      : '';
    return client.post<AuthRequirements>(
      `${realmSegment}/authenticate${queryString}`,
      '',
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Submit callback requirements and receive next stage.
   * @param requirements - The current requirements (including authId)
   * @param realm - The realm path (e.g., 'root', 'b2c/clients')
   * @param params - Additional URL parameters
   */
  submitRequirements(
    requirements: AuthRequirements,
    realm: string,
    params?: Record<string, string>,
  ): Promise<AuthRequirements> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? `/${realm}` : '';
    const queryString = params
      ? '?' + new URLSearchParams(params).toString()
      : '';
    return client.post<AuthRequirements>(
      `${realmSegment}/authenticate${queryString}`,
      requirements,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Validate a goto URL for post-login redirect.
   */
  validateGoto(goto: string): Promise<{ valid: boolean }> {
    const client = new RestClient(buildBaseUrl());
    return client.post<{ valid: boolean }>(
      '/users?_action=validateGoto',
      { goto: decodeURIComponent(goto) },
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=2.0' } },
    );
  },

  /**
   * Get server info for authentication configuration.
   */
  getServerInfo(): Promise<{ cookieName: string; [key: string]: unknown }> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ cookieName: string; [key: string]: unknown }>(
      '/serverinfo/*',
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.1' } },
    );
  },
};
