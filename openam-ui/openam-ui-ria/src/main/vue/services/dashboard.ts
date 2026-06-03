import { RestClient } from './api';
import { Constants } from './constants';
import type { TrustedDevice, OathDevice, DashboardApplication } from '@/types/user';

const API_VERSION = 'protocol=1.0,resource=1.0';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

function userPath(username: string): string {
  return `/users/${encodeURIComponent(username)}`;
}

/**
 * Dashboard REST operations.
 *
 * Combines TrustedDevicesService, DeviceManagementService,
 * MyApplicationsService, and OAuthTokensService.
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const dashboardApi = {
  // -------------------------------------------------------------------------
  // Trusted Devices
  // -------------------------------------------------------------------------

  /**
   * Get all trusted devices for the current user.
   */
  getTrustedDevices(username: string): Promise<TrustedDevice[]> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ result: TrustedDevice[] }>(
      `${userPath(username)}/devices/trusted/?_queryId=*`,
      { headers: { 'Cache-Control': 'no-cache', 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.result);
  },

  /**
   * Delete a trusted device by ID.
   */
  deleteTrustedDevice(username: string, deviceId: string): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.delete<void>(
      `${userPath(username)}/devices/trusted/${encodeURIComponent(deviceId)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // OATH Devices (2FA)
  // -------------------------------------------------------------------------

  /**
   * Get all OATH devices for the current user.
   */
  getOathDevices(username: string): Promise<OathDevice[]> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ result: OathDevice[] }>(
      `${userPath(username)}/devices/2fa/oath?_queryFilter=true`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.result);
  },

  /**
   * Delete an OATH device by UUID.
   */
  deleteOathDevice(username: string, uuid: string): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.delete<void>(
      `${userPath(username)}/devices/2fa/oath/${encodeURIComponent(uuid)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Check if OATH skip is enabled for the user.
   */
  checkOathSkippable(username: string): Promise<boolean> {
    const client = new RestClient(buildBaseUrl());
    return client.post<{ result: boolean }>(
      `${userPath(username)}/devices/2fa/oath?_action=check`,
      {},
      { headers: { 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.result);
  },

  /**
   * Set the OATH skip flag for the user.
   */
  setOathSkippable(username: string, skip: boolean): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `${userPath(username)}/devices/2fa/oath?_action=skip`,
      { value: skip },
      { headers: { 'Accept-API-Version': API_VERSION } },
    ).then(() => undefined);
  },

  // -------------------------------------------------------------------------
  // Applications
  // -------------------------------------------------------------------------

  /**
   * Get assigned applications for the current user.
   */
  getMyApplications(username: string): Promise<DashboardApplication[]> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ result: DashboardApplication[] }>(
      `${userPath(username)}/oauth2/applications?_queryFilter=true`,
      { headers: { 'Cache-Control': 'no-cache', 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.result);
  },

  /**
   * Get available applications for the current user.
   */
  getAvailableApplications(username: string): Promise<DashboardApplication[]> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ result: DashboardApplication[] }>(
      `${userPath(username)}/oauth2/applications?_queryFilter=true`,
      { headers: { 'Cache-Control': 'no-cache', 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.result);
  },

  /**
   * Revoke an application by ID.
   */
  revokeApplication(username: string, applicationId: string): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.delete<void>(
      `${userPath(username)}/oauth2/applications/${encodeURIComponent(applicationId)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // Dashboard config
  // -------------------------------------------------------------------------

  /**
   * Get dashboard configuration.
   */
  getDashboardConfig(): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.get(
      '/dashboard/config',
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },
};
