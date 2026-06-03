import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGet = vi.fn();
const mockPost = vi.fn();

vi.mock('@/services/api', () => {
  return {
    RestClient: class MockRestClient {
      get = mockGet;
      post = mockPost;
      put = vi.fn();
      patch = vi.fn();
      delete = vi.fn();
    },
  };
});

import { sessionApi } from '@/services/session';

describe('session service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getSessionInfo', () => {
    it('fetches current session info', async () => {
      const mockSession = {
        tokenId: 'token-123',
        uid: 'testuser',
        realm: '/realms/root',
        username: 'testuser',
      };
      mockPost.mockResolvedValue(mockSession);

      const result = await sessionApi.getSessionInfo();

      expect(mockPost).toHaveBeenCalledWith(
        '/sessions?_action=getSessionInfo',
        {},
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=1.1'),
          }),
        }),
      );
      expect(result).toEqual(mockSession);
    });
  });

  describe('destroySession', () => {
    it('destroys a session by token ID', async () => {
      mockPost.mockResolvedValue({});

      await sessionApi.destroySession('token-123');

      expect(mockPost).toHaveBeenCalledWith(
        '/sessions/token-123?_action=destroy',
        {},
        expect.any(Object),
      );
    });

    it('encodes token ID in URL', async () => {
      mockPost.mockResolvedValue({});

      await sessionApi.destroySession('token/with/slashes');

      expect(mockPost).toHaveBeenCalledWith(
        '/sessions/token%2Fwith%2Fslashes?_action=destroy',
        expect.any(Object),
        expect.any(Object),
      );
    });
  });

  describe('getSessionProperties', () => {
    it('fetches session properties', async () => {
      const mockProperties = { locale: 'en', timezone: 'UTC' };
      mockGet.mockResolvedValue(mockProperties);

      const result = await sessionApi.getSessionProperties('token-123');

      expect(mockGet).toHaveBeenCalledWith(
        '/sessions/token-123/properties',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=1.1'),
          }),
        }),
      );
      expect(result).toEqual(mockProperties);
    });
  });
});
