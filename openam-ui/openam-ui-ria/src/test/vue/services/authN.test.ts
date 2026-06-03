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

import { authNApi } from '@/services/authN';

describe('authN service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('begin', () => {
    it('starts authentication with POST to /authenticate', async () => {
      const mockRequirements = { authId: 'auth-123', callbacks: [] };
      mockPost.mockResolvedValue(mockRequirements);

      const result = await authNApi.begin('/realms/root');

      expect(mockPost).toHaveBeenCalledWith(
        '/authenticate/realms/root',
        '',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=2.1'),
          }),
        }),
      );
      expect(result).toEqual(mockRequirements);
    });

    it('appends query params to URL', async () => {
      mockPost.mockResolvedValue({});

      await authNApi.begin('/realms/root', {
        authIndexType: 'service',
        authIndexValue: 'ldap',
      });

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('authIndexType=service'),
        '',
        expect.any(Object),
      );
    });

    it('handles empty realm', async () => {
      mockPost.mockResolvedValue({});

      await authNApi.begin('');

      expect(mockPost).toHaveBeenCalledWith(
        '/authenticate',
        '',
        expect.any(Object),
      );
    });
  });

  describe('submitRequirements', () => {
    it('submits callback requirements', async () => {
      const requirements = {
        authId: 'auth-123',
        callbacks: [{ type: 'PasswordCallback', output: [], input: [{ name: 'password', value: 'pass' }] }],
      };
      mockPost.mockResolvedValue({ tokenId: 'session-123' });

      const result = await authNApi.submitRequirements(requirements, '/realms/root');

      expect(mockPost).toHaveBeenCalledWith(
        '/authenticate/realms/root',
        requirements,
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=2.1'),
          }),
        }),
      );
      expect(result).toEqual({ tokenId: 'session-123' });
    });

    it('includes additional params', async () => {
      mockPost.mockResolvedValue({});

      await authNApi.submitRequirements(
        { authId: 'auth-123' },
        '/realms/root',
        { authIndexType: 'service' },
      );

      expect(mockPost).toHaveBeenCalledWith(
        expect.stringContaining('authIndexType=service'),
        expect.any(Object),
        expect.any(Object),
      );
    });
  });

  describe('validateGoto', () => {
    it('validates goto URL', async () => {
      mockPost.mockResolvedValue({ valid: true });

      const result = await authNApi.validateGoto('https://example.com');

      expect(mockPost).toHaveBeenCalledWith(
        '/users?_action=validateGoto',
        { goto: 'https://example.com' },
        expect.any(Object),
      );
      expect(result).toEqual({ valid: true });
    });
  });

  describe('getServerInfo', () => {
    it('fetches server info', async () => {
      const mockInfo = { cookieName: 'iPlanetDirectoryPro' };
      mockGet.mockResolvedValue(mockInfo);

      const result = await authNApi.getServerInfo();

      expect(mockGet).toHaveBeenCalledWith(
        '/serverinfo/*',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=1.1'),
          }),
        }),
      );
      expect(result).toEqual(mockInfo);
    });
  });
});
