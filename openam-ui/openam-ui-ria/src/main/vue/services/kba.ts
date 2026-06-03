import { RestClient } from './api';
import { Constants } from './constants';
import type { KBAQuestion, KBAInfo } from '@/types/user';

const API_VERSION = 'protocol=1.0,resource=1.0';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

/**
 * KBA (Knowledge-Based Authentication) REST operations.
 *
 * Provides operations for managing security questions during
 * password reset and self-registration flows.
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const kbaApi = {
  /**
   * Get available predefined KBA questions for a realm.
   * @param realm - The realm path
   */
  getPredefinedQuestions(realm: string): Promise<string[]> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? realm.replace(/^\//, '') : '';
    const realmParam = realmSegment ? `/${realmSegment}` : '';
    return client.get<{ predefinedQuestions: string[] }>(
      `/selfservice/kbaOptions${realmParam}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.predefinedQuestions);
  },

  /**
   * Submit KBA questions and answers as part of a self-service process.
   * @param endpoint - The self-service endpoint (e.g., 'selfservice/forgottenPassword')
   * @param realm - The realm path
   * @param token - The process token
   * @param kbaInfo - Array of KBA questions and answers
   */
  submitKbaAnswers(
    endpoint: string,
    realm: string,
    token: string,
    kbaInfo: KBAInfo,
  ): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? realm.replace(/^\//, '') : '';
    const realmParam = realmSegment ? `/${realmSegment}` : '';
    return client.post(
      `/${endpoint}${realmParam}`,
      { token, kbaInfo },
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Validate KBA answers for a user.
   * @param username - The username to validate against
   * @param kbaInfo - Array of KBA questions and answers to validate
   */
  validateKbaAnswers(
    username: string,
    kbaInfo: KBAInfo,
  ): Promise<{ valid: boolean }> {
    const client = new RestClient(buildBaseUrl());
    return client.post<{ valid: boolean }>(
      `/users/${encodeURIComponent(username)}?_action=validateKbaAnswers`,
      { kbaInfo },
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Get KBA info for a user (admin operation).
   * @param username - The username
   */
  getUserKbaInfo(username: string): Promise<KBAInfo> {
    const client = new RestClient(buildBaseUrl());
    return client.get<KBAInfo>(
      `/users/${encodeURIComponent(username)}/kbaInfo`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Update KBA info for a user (admin operation).
   * @param username - The username
   * @param kbaInfo - New KBA info to set
   */
  updateUserKbaInfo(
    username: string,
    kbaInfo: KBAInfo,
  ): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `/users/${encodeURIComponent(username)}?_action=updateKbaInfo`,
      { kbaInfo },
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },
};
