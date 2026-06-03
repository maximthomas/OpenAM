import { RestClient } from './api';
import { Constants } from './constants';
import type { UserProfile, UserProfileUpdate, ChangePasswordPayload } from '@/types/user';

const API_VERSION = 'protocol=1.0,resource=2.0';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

/**
 * User profile REST operations.
 *
 * All methods use the existing RestClient — no error suppression.
 * Callers are expected to handle errors via useAlert().danger().
 */
export const userApi = {
  /**
   * Read the current user's profile.
   * @param username - The user's AM username (uid)
   */
  read(username: string): Promise<UserProfile> {
    const client = new RestClient(buildBaseUrl());
    return client.get<UserProfile>(
      `/users/${encodeURIComponent(username)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Update the current user's profile attributes (excluding password).
   * Uses PUT with If-Match for MVCC.
   */
  update(
    username: string,
    data: UserProfileUpdate,
    rev: string,
    currentPassword?: string,
  ): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    const headers: Record<string, string> = {
      'Accept-API-Version': API_VERSION,
      'If-Match': `"${rev}"`,
    };
    if (currentPassword) {
      headers.currentpassword = currentPassword;
    }
    return client.put(
      `/users/${encodeURIComponent(username)}`,
      data,
      { headers },
    );
  },

  /**
   * Change the current user's password.
   * Requires the current password and the new password.
   */
  changePassword(payload: ChangePasswordPayload): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `/users/${encodeURIComponent(payload.username)}?_action=changePassword`,
      {
        username: payload.username,
        currentpassword: payload.currentpassword,
        userpassword: payload.userpassword,
      },
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=2.0' } },
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
};
