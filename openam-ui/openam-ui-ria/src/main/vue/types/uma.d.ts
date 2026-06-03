/**
 * UMA (User-Managed Access) type definitions for OpenAM UI.
 * Covers resource sets, labels, permissions, requests, and policy.
 */

// ---------------------------------------------------------------------------
// UMA Resource Sets
// ---------------------------------------------------------------------------

export interface UMAResourceSet {
  _id: string;
  name: string;
  description?: string;
  type?: string[];
  uri?: string;
  owner: string;
  ownerAsUUID?: string;
  ownerFullName?: string;
  created: string;
  lastModified: string;
  labels?: string[];
  scopes: string[];
  resourceAttributes?: Record<string, string[]>;
}

export interface UMAResourceSetCreate {
  name: string;
  description?: string;
  type?: string[];
  uri?: string;
  scopes: string[];
  labels?: string[];
}

// ---------------------------------------------------------------------------
// UMA Permissions
// ---------------------------------------------------------------------------

export interface UMAPermission {
  type: string;
  scopes: string[];
  subject: string;
  actions?: string[];
}

export interface UMAPolicy {
  _id: string;
  name: string;
  description?: string;
  resourceType: string;
  resources: string[];
  subject: string;
  permissions: UMAPermission[];
  created: string;
  lastModified: string;
}

export interface UMAPolicyCreate {
  name: string;
  description?: string;
  resourceType: string;
  resources: string[];
  subject: string;
  permissions: UMAPermission[];
}

// ---------------------------------------------------------------------------
// UMA Labels
// ---------------------------------------------------------------------------

export interface UMALabel {
  _id: string;
  name: string;
  type: 'default' | 'starred';
  owner: string;
  created: string;
  lastModified: string;
}

export interface UMALabelCreate {
  name: string;
  type: 'default' | 'starred';
}

// ---------------------------------------------------------------------------
// UMA Requests
// ---------------------------------------------------------------------------

export interface UMARequest {
  _id: string;
  resourceSetId: string;
  resourceSetName: string;
  resourceSetType?: string[];
  requester: string;
  requesterFullName?: string;
  scopes: string[];
  status: 'pending' | 'approved' | 'denied';
  created: string;
  lastModified: string;
}

export interface UMARequestApproval {
  scopes: string[];
}

// ---------------------------------------------------------------------------
// UMA History
// ---------------------------------------------------------------------------

export interface UMAHistoryEntry {
  _id: string;
  resourceSetId: string;
  resourceSetName: string;
  action: 'approve' | 'deny' | 'revoke' | 'request';
  subject: string;
  subjectFullName?: string;
  scopes?: string[];
  created: string;
}

// ---------------------------------------------------------------------------
// UMA Configuration
// ---------------------------------------------------------------------------

export interface UMAConfig {
  enabled: boolean;
  resharingMode: boolean;
}

// ---------------------------------------------------------------------------
// Server-side Pagination (used by UMA resource listing)
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
  result: T[];
  resultCount: number;
  remainingPagedResults: number;
  pagedResultsCookie?: string;
}

export interface PaginationParams {
  _pageSize?: number;
  _pagedResultsOffset?: number;
  _sortKeys?: string;
  _queryFilter?: string;
  _queryId?: string;
}
