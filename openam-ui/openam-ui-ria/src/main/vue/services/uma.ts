import { RestClient } from './api';
import { Constants } from './constants';
import type {
  UMAResourceSet,
  UMAResourceSetCreate,
  UMALabel,
  UMALabelCreate,
  UMARequest,
  UMARequestApproval,
  UMAHistoryEntry,
  UMAConfig,
  PaginatedResponse,
  PaginationParams,
} from '@/types/uma';

const API_VERSION = 'protocol=1.0,resource=1.0';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

function userPath(username: string): string {
  return `/users/${encodeURIComponent(username)}`;
}

/**
 * UMA (User-Managed Access) REST operations.
 *
 * No error suppression — callers handle errors via useAlert().danger().
 */
export const umaApi = {
  // -------------------------------------------------------------------------
  // Configuration
  // -------------------------------------------------------------------------

  /**
   * Get UMA configuration from serverinfo.
   */
  getUmaConfig(): Promise<UMAConfig> {
    const client = new RestClient(buildBaseUrl());
    return client.get<UMAConfig>(
      '/serverinfo/uma',
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.0' } },
    );
  },

  // -------------------------------------------------------------------------
  // Resource Sets
  // -------------------------------------------------------------------------

  /**
   * Get all resource sets for a user with server-side pagination.
   */
  getResourceSets(
    username: string,
    params?: PaginationParams,
  ): Promise<PaginatedResponse<UMAResourceSet>> {
    const client = new RestClient(buildBaseUrl());
    const query = buildPaginationQuery(params);
    return client.get<PaginatedResponse<UMAResourceSet>>(
      `${userPath(username)}/oauth2/resources/sets?${query}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Get a single resource set by ID.
   */
  getResourceSet(username: string, resourceId: string): Promise<UMAResourceSet> {
    const client = new RestClient(buildBaseUrl());
    return client.get<UMAResourceSet>(
      `${userPath(username)}/oauth2/resources/sets/${encodeURIComponent(resourceId)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Create a new resource set.
   */
  createResourceSet(
    username: string,
    data: UMAResourceSetCreate,
  ): Promise<UMAResourceSet> {
    const client = new RestClient(buildBaseUrl());
    return client.post<UMAResourceSet>(
      `${userPath(username)}/oauth2/resources/sets?_action=create`,
      data,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Update an existing resource set.
   */
  updateResourceSet(
    username: string,
    resourceId: string,
    data: Partial<UMAResourceSetCreate>,
  ): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.put(
      `${userPath(username)}/oauth2/resources/sets/${encodeURIComponent(resourceId)}`,
      data,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Delete a resource set.
   */
  deleteResourceSet(username: string, resourceId: string): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.delete<void>(
      `${userPath(username)}/oauth2/resources/sets/${encodeURIComponent(resourceId)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Unshare (revoke) all resources for the user.
   */
  unshareAllResources(username: string): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `${userPath(username)}/oauth2/resources/sets?_action=revokeAll`,
      {},
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // Labels
  // -------------------------------------------------------------------------

  /**
   * Get all labels for a user.
   */
  getLabels(username: string): Promise<UMALabel[]> {
    const client = new RestClient(buildBaseUrl());
    return client.get<{ result: UMALabel[] }>(
      `${userPath(username)}/oauth2/resources/labels?_queryFilter=true`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    ).then((response) => response.result);
  },

  /**
   * Create a new label.
   */
  createLabel(
    username: string,
    data: UMALabelCreate,
  ): Promise<UMALabel> {
    const client = new RestClient(buildBaseUrl());
    return client.post<UMALabel>(
      `${userPath(username)}/oauth2/resources/labels?_action=create`,
      data,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Delete a label by ID.
   */
  deleteLabel(username: string, labelId: string): Promise<void> {
    const client = new RestClient(buildBaseUrl());
    return client.delete<void>(
      `${userPath(username)}/oauth2/resources/labels/${encodeURIComponent(labelId)}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // Pending Requests
  // -------------------------------------------------------------------------

  /**
   * Get pending requests for the user.
   */
  getPendingRequests(
    username: string,
    params?: PaginationParams,
  ): Promise<PaginatedResponse<UMARequest>> {
    const client = new RestClient(buildBaseUrl());
    const query = buildPaginationQuery(params);
    return client.get<PaginatedResponse<UMARequest>>(
      `${userPath(username)}/uma/pendingrequests?${query}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Approve a pending request.
   */
  approveRequest(
    username: string,
    requestId: string,
    data: UMARequestApproval,
  ): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `${userPath(username)}/uma/pendingrequests/${encodeURIComponent(requestId)}?_action=approve`,
      data,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  /**
   * Deny a pending request.
   */
  denyRequest(username: string, requestId: string): Promise<unknown> {
    const client = new RestClient(buildBaseUrl());
    return client.post(
      `${userPath(username)}/uma/pendingrequests/${encodeURIComponent(requestId)}?_action=deny`,
      {},
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // History
  // -------------------------------------------------------------------------

  /**
   * Get UMA history for the user.
   */
  getHistory(
    username: string,
    params?: PaginationParams,
  ): Promise<PaginatedResponse<UMAHistoryEntry>> {
    const client = new RestClient(buildBaseUrl());
    const query = buildPaginationQuery(params);
    return client.get<PaginatedResponse<UMAHistoryEntry>>(
      `${userPath(username)}/uma/history?${query}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // Shared With Me
  // -------------------------------------------------------------------------

  /**
   * Get resources shared with the current user.
   */
  getSharedWithMe(
    username: string,
    params?: PaginationParams,
  ): Promise<PaginatedResponse<UMAResourceSet>> {
    const client = new RestClient(buildBaseUrl());
    const query = buildPaginationQuery(params);
    return client.get<PaginatedResponse<UMAResourceSet>>(
      `${userPath(username)}/oauth2/resources/sets?_queryFilter=true&${query}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },

  // -------------------------------------------------------------------------
  // Starred
  // -------------------------------------------------------------------------

  /**
   * Get starred (favorite) resources for the user.
   */
  getStarredResources(
    username: string,
    params?: PaginationParams,
  ): Promise<PaginatedResponse<UMAResourceSet>> {
    const client = new RestClient(buildBaseUrl());
    const query = buildPaginationQuery(params);
    return client.get<PaginatedResponse<UMAResourceSet>>(
      `${userPath(username)}/oauth2/resources/sets?_queryFilter=labels+eq+%22starred%22&${query}`,
      { headers: { 'Accept-API-Version': API_VERSION } },
    );
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPaginationQuery(params?: PaginationParams): string {
  if (!params) {
    return '_queryFilter=true';
  }
  const parts: string[] = [];
  if (params._pageSize !== undefined) {
    parts.push(`_pageSize=${params._pageSize}`);
  }
  if (params._pagedResultsOffset !== undefined) {
    parts.push(`_pagedResultsOffset=${params._pagedResultsOffset}`);
  }
  if (params._sortKeys) {
    parts.push(`_sortKeys=${encodeURIComponent(params._sortKeys)}`);
  }
  if (params._queryFilter) {
    parts.push(`_queryFilter=${encodeURIComponent(params._queryFilter)}`);
  }
  if (params._queryId) {
    parts.push(`_queryId=${params._queryId}`);
  }
  return parts.length > 0 ? parts.join('&') : '_queryFilter=true';
}
