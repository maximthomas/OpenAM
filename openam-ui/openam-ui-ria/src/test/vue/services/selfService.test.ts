import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockPost = vi.fn();

vi.mock('@/services/api', () => {
  return {
    RestClient: class MockRestClient {
      get = vi.fn();
      post = mockPost;
      put = vi.fn();
      patch = vi.fn();
      delete = vi.fn();
    },
  };
});

import { selfServiceApi } from '@/services/selfService';

describe('selfService service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('begin', () => {
    it('starts a self-service process', async () => {
      const mockState = {
        stage: { type: 'username', tag: 'initial', callbacks: [] },
      };
      mockPost.mockResolvedValue(mockState);

      const result = await selfServiceApi.begin(
        'selfservice/forgottenPassword',
        'root',
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/root/selfservice/forgottenPassword',
        {},
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=1.0'),
          }),
        }),
      );
      expect(result).toEqual(mockState);
    });

    it('includes token for email link continuation', async () => {
      mockPost.mockResolvedValue({});

      await selfServiceApi.begin(
        'selfservice/forgottenPassword',
        'root',
        'token-from-email',
      );

      expect(mockPost).toHaveBeenCalledWith(
        expect.any(String),
        { token: 'token-from-email' },
        expect.any(Object),
      );
    });

    it('handles nested realm', async () => {
      mockPost.mockResolvedValue({});

      await selfServiceApi.begin('selfservice/userRegistration', 'b2c/clients');

      expect(mockPost).toHaveBeenCalledWith(
        '/b2c/clients/selfservice/userRegistration',
        {},
        expect.any(Object),
      );
    });

    it('handles empty realm', async () => {
      mockPost.mockResolvedValue({});

      await selfServiceApi.begin('selfservice/userRegistration', '');

      expect(mockPost).toHaveBeenCalledWith(
        '/selfservice/userRegistration',
        {},
        expect.any(Object),
      );
    });
  });

  describe('submitRequirements', () => {
    it('submits requirements for a self-service process', async () => {
      const requirements = { authId: 'auth-123', callbacks: [] };
      mockPost.mockResolvedValue({});

      await selfServiceApi.submitRequirements(
        'selfservice/forgottenPassword',
        'root',
        requirements,
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/root/selfservice/forgottenPassword',
        requirements,
        expect.any(Object),
      );
    });
  });

  describe('getRequirements', () => {
    it('fetches initial requirements', async () => {
      const mockRequirements = { callbacks: [] };
      mockPost.mockResolvedValue(mockRequirements);

      const result = await selfServiceApi.getRequirements(
        'selfservice/userRegistration',
        'root',
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/root/selfservice/userRegistration',
        {},
        expect.any(Object),
      );
      expect(result).toEqual(mockRequirements);
    });
  });

  describe('validateGoto', () => {
    it('validates goto URL', async () => {
      mockPost.mockResolvedValue({ valid: true });

      const result = await selfServiceApi.validateGoto('https://example.com');

      expect(mockPost).toHaveBeenCalledWith(
        '/users?_action=validateGoto',
        { goto: 'https://example.com' },
        expect.any(Object),
      );
      expect(result).toEqual({ valid: true });
    });
  });
});
