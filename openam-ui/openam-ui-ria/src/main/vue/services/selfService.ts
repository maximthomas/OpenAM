import { RestClient } from './api';
import { Constants } from './constants';
import type { SelfServiceProcessState, AuthRequirements } from '@/types/user';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

/**
 * Self-Service REST operations.
 *
 * Covers password reset, forgotten username, and user registration.
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const selfServiceApi = {
  /**
   * Begin a self-service process (password reset, forgot username, registration).
   * @param endpoint - The self-service endpoint path (e.g., 'selfservice/forgottenPassword')
   * @param realm - The realm path (e.g., 'root', 'b2c/clients')
   * @param token - Optional token for continuing a process (from email link)
   */
  begin(
    endpoint: string,
    realm: string,
    token?: string,
  ): Promise<SelfServiceProcessState> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? `/${realm}` : '';
    const body: Record<string, unknown> = {};
    if (token) {
      body.token = token;
    }
    return client.post<SelfServiceProcessState>(
      `${realmSegment}/${endpoint}`,
      body,
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.0' } },
    );
  },

  /**
   * Submit requirements for a self-service process.
   * @param endpoint - The self-service endpoint path
   * @param realm - The realm path (e.g., 'root', 'b2c/clients')
   * @param requirements - The current requirements to submit
   */
  submitRequirements(
    endpoint: string,
    realm: string,
    requirements: AuthRequirements,
  ): Promise<SelfServiceProcessState> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? `/${realm}` : '';
    return client.post<SelfServiceProcessState>(
      `${realmSegment}/${endpoint}`,
      requirements,
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.0' } },
    );
  },

  /**
   * Get the initial requirements for a self-service process.
   * This is the first step in the process flow.
   * @param endpoint - The self-service endpoint path
   * @param realm - The realm path (e.g., 'root', 'b2c/clients')
   */
  getRequirements(
    endpoint: string,
    realm: string,
  ): Promise<AuthRequirements> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? `/${realm}` : '';
    return client.post<AuthRequirements>(
      `${realmSegment}/${endpoint}`,
      {},
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.0' } },
    );
  },

  /**
   * Validate a goto URL for post-registration redirect.
   */
  validateGoto(goto: string): Promise<{ valid: boolean }> {
    const client = new RestClient(buildBaseUrl());
    return client.post<{ valid: boolean }>(
      '/users?_action=validateGoto',
      { goto: decodeURIComponent(goto) },
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=2.0' } },
    );
  },
};
