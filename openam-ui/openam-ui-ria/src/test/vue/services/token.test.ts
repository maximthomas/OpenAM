import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGet = vi.fn();
const mockDelete = vi.fn();

vi.mock('@/services/api', () => {
  return {
    RestClient: class MockRestClient {
      get = mockGet;
      post = vi.fn();
      put = vi.fn();
      patch = vi.fn();
      delete = mockDelete;
    },
  };
});

import { tokenApi } from '@/services/token';

describe('token service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getAllTokens', () => {
    it('fetches all OAuth2 tokens', async () => {
      const mockTokens = {
        result: [
          { _id: 'token-1', clientId: 'client-1', type: 'access_token' },
          { _id: 'token-2', clientId: 'client-2', type: 'refresh_token' },
        ],
      };
      mockGet.mockResolvedValue(mockTokens);

      const result = await tokenApi.getAllTokens();

      expect(mockGet).toHaveBeenCalledWith(
        '/?_queryid=*',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Cache-Control': 'no-cache',
          }),
        }),
      );
      expect(result).toEqual(mockTokens.result);
    });
  });

  describe('deleteToken', () => {
    it('deletes a token by ID', async () => {
      mockDelete.mockResolvedValue(undefined);

      await tokenApi.deleteToken('token-123');

      expect(mockDelete).toHaveBeenCalledWith(
        '/token-123',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Cache-Control': 'no-cache',
          }),
        }),
      );
    });

    it('encodes token ID in URL', async () => {
      mockDelete.mockResolvedValue(undefined);

      await tokenApi.deleteToken('token/with/slashes');

      expect(mockDelete).toHaveBeenCalledWith(
        '/token%2Fwith%2Fslashes',
        expect.any(Object),
      );
    });
  });

  describe('getTokenById', () => {
    it('fetches a token by ID', async () => {
      const mockToken = { _id: 'token-123', clientId: 'client-1', type: 'access_token' };
      mockGet.mockResolvedValue(mockToken);

      const result = await tokenApi.getTokenById('token-123');

      expect(mockGet).toHaveBeenCalledWith(
        '/token-123',
        expect.any(Object),
      );
      expect(result).toEqual(mockToken);
    });
  });
});
