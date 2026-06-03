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
        '/realms/root',
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/selfservice/forgottenPassword/realms/root',
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
        '/realms/root',
        'token-from-email',
      );

      expect(mockPost).toHaveBeenCalledWith(
        expect.any(String),
        { token: 'token-from-email' },
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
        '/realms/root',
        requirements,
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/selfservice/forgottenPassword/realms/root',
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
        '/realms/root',
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/selfservice/userRegistration/realms/root',
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
