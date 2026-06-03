import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGet = vi.fn();
const mockPost = vi.fn();
const mockPut = vi.fn();
const mockDelete = vi.fn();

vi.mock('@/services/api', () => {
  return {
    RestClient: class MockRestClient {
      get = mockGet;
      post = mockPost;
      put = mockPut;
      patch = vi.fn();
      delete = mockDelete;
    },
  };
});

import { umaApi } from '@/services/uma';

describe('uma service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getUmaConfig', () => {
    it('fetches UMA configuration', async () => {
      const mockConfig = { enabled: true, resharingMode: false };
      mockGet.mockResolvedValue(mockConfig);

      const result = await umaApi.getUmaConfig();

      expect(mockGet).toHaveBeenCalledWith(
        '/serverinfo/uma',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=1.0'),
          }),
        }),
      );
      expect(result).toEqual(mockConfig);
    });
  });

  describe('getResourceSets', () => {
    it('fetches resource sets with default pagination', async () => {
      const mockResponse = {
        result: [{ _id: 'resource-1', name: 'Test Resource' }],
        resultCount: 1,
        remainingPagedResults: 0,
      };
      mockGet.mockResolvedValue(mockResponse);

      const result = await umaApi.getResourceSets('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        expect.stringContaining('/users/testuser/oauth2/resources/sets'),
        expect.any(Object),
      );
      expect(result).toEqual(mockResponse);
    });

    it('applies pagination params', async () => {
      mockGet.mockResolvedValue({ result: [], resultCount: 0, remainingPagedResults: 0 });

      await umaApi.getResourceSets('testuser', {
        _pageSize: 10,
        _pagedResultsOffset: 20,
        _sortKeys: '-created',
      });

      expect(mockGet).toHaveBeenCalledWith(
        expect.stringContaining('_pageSize=10'),
        expect.any(Object),
      );
    });
  });

  describe('createResourceSet', () => {
    it('creates a new resource set', async () => {
      const mockResource = { _id: 'new-1', name: 'New Resource' };
      mockPost.mockResolvedValue(mockResource);

      const result = await umaApi.createResourceSet('testuser', {
        name: 'New Resource',
        scopes: ['view', 'edit'],
      });

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('?_action=create'),
        expect.objectContaining({ name: 'New Resource' }),
        expect.any(Object),
      );
      expect(result).toEqual(mockResource);
    });
  });

  describe('deleteResourceSet', () => {
    it('deletes a resource set', async () => {
      mockDelete.mockResolvedValue(undefined);

      await umaApi.deleteResourceSet('testuser', 'resource-123');

      expect(mockDelete).toHaveBeenCalledWith(
        expect.stringContaining('/resource-123'),
        expect.any(Object),
      );
    });
  });

  describe('getLabels', () => {
    it('fetches all labels', async () => {
      const mockLabels = {
        result: [
          { _id: 'label-1', name: 'Important', type: 'default' },
          { _id: 'label-2', name: 'Starred', type: 'starred' },
        ],
      };
      mockGet.mockResolvedValue(mockLabels);

      const result = await umaApi.getLabels('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        expect.stringContaining('/oauth2/resources/labels'),
        expect.any(Object),
      );
      expect(result).toEqual(mockLabels.result);
    });
  });

  describe('createLabel', () => {
    it('creates a new label', async () => {
      const mockLabel = { _id: 'label-1', name: 'New Label', type: 'default' };
      mockPost.mockResolvedValue(mockLabel);

      const result = await umaApi.createLabel('testuser', {
        name: 'New Label',
        type: 'default',
      });

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('?_action=create'),
        expect.objectContaining({ name: 'New Label' }),
        expect.any(Object),
      );
      expect(result).toEqual(mockLabel);
    });
  });

  describe('deleteLabel', () => {
    it('deletes a label', async () => {
      mockDelete.mockResolvedValue(undefined);

      await umaApi.deleteLabel('testuser', 'label-123');

      expect(mockDelete).toHaveBeenCalledWith(
        expect.stringContaining('/label-123'),
        expect.any(Object),
      );
    });
  });

  describe('approveRequest', () => {
    it('approves a pending request with scopes', async () => {
      mockPost.mockResolvedValue({});

      await umaApi.approveRequest('testuser', 'request-123', {
        scopes: ['view', 'edit'],
      });

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('?_action=approve'),
        { scopes: ['view', 'edit'] },
        expect.any(Object),
      );
    });
  });

  describe('denyRequest', () => {
    it('denies a pending request', async () => {
      mockPost.mockResolvedValue({});

      await umaApi.denyRequest('testuser', 'request-123');

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('?_action=deny'),
        {},
        expect.any(Object),
      );
    });
  });

  describe('getHistory', () => {
    it('fetches UMA history', async () => {
      const mockHistory = {
        result: [
          { _id: 'history-1', action: 'approve', resourceSetName: 'Test' },
        ],
        resultCount: 1,
        remainingPagedResults: 0,
      };
      mockGet.mockResolvedValue(mockHistory);

      const result = await umaApi.getHistory('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        expect.stringContaining('/uma/history'),
        expect.any(Object),
      );
      expect(result).toEqual(mockHistory);
    });
  });

  describe('unshareAllResources', () => {
    it('revokes all shared resources', async () => {
      mockPost.mockResolvedValue({});

      await umaApi.unshareAllResources('testuser');

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('?_action=revokeAll'),
        {},
        expect.any(Object),
      );
    });
  });
});
