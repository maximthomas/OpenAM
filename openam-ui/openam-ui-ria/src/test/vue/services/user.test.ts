import { describe, it, expect, vi, beforeEach } from 'vitest';

// Create shared mock instances
const mockGet = vi.fn();
const mockPost = vi.fn();
const mockPut = vi.fn();
const mockPatch = vi.fn();
const mockDelete = vi.fn();

// Mock RestClient as a class
vi.mock('@/services/api', () => {
  return {
    RestClient: class MockRestClient {
      get = mockGet;
      post = mockPost;
      put = mockPut;
      patch = mockPatch;
      delete = mockDelete;
    },
  };
});

import { userApi } from '@/services/user';

describe('user service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('read', () => {
    it('fetches user profile by username', async () => {
      const mockUser = { _id: '1', uid: 'testuser', username: 'testuser' };
      mockGet.mockResolvedValue(mockUser);

      const result = await userApi.read('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        '/users/testuser',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=2.0'),
          }),
        }),
      );
      expect(result).toEqual(mockUser);
    });

    it('encodes username in URL', async () => {
      mockGet.mockResolvedValue({});

      await userApi.read('user@example.com');

      expect(mockGet).toHaveBeenCalledWith(
        '/users/user%40example.com',
        expect.any(Object),
      );
    });
  });

  describe('update', () => {
    it('updates user profile with PUT', async () => {
      mockPut.mockResolvedValue({});

      const data = { givenName: 'John', sn: 'Doe', mail: 'john@example.com' };
      await userApi.update('testuser', data, 'rev-123');

      expect(mockPut).toHaveBeenCalledWith(
        '/users/testuser',
        data,
        expect.objectContaining({
          headers: expect.objectContaining({
            'If-Match': '"rev-123"',
          }),
        }),
      );
    });

    it('includes currentPassword header when provided', async () => {
      mockPut.mockResolvedValue({});

      await userApi.update(
        'testuser',
        { givenName: 'John', sn: 'Doe', mail: 'john@example.com' },
        'rev-123',
        'oldPassword',
      );

      expect(mockPut).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Object),
        expect.objectContaining({
          headers: expect.objectContaining({
            currentpassword: 'oldPassword',
          }),
        }),
      );
    });
  });

  describe('changePassword', () => {
    it('posts password change request', async () => {
      mockPost.mockResolvedValue({});

      await userApi.changePassword({
        username: 'testuser',
        currentpassword: 'oldPass',
        userpassword: 'newPass',
      });

      expect(mockPost).toHaveBeenCalledWith(
        '/users/testuser?_action=changePassword',
        {
          username: 'testuser',
          currentpassword: 'oldPass',
          userpassword: 'newPass',
        },
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=2.0'),
          }),
        }),
      );
    });
  });

  describe('validateGoto', () => {
    it('validates goto URL', async () => {
      mockPost.mockResolvedValue({ valid: true });

      const result = await userApi.validateGoto('https://example.com');

      expect(mockPost).toHaveBeenCalledWith(
        '/users?_action=validateGoto',
        { goto: 'https://example.com' },
        expect.any(Object),
      );
      expect(result).toEqual({ valid: true });
    });

    it('decodes encoded goto URL', async () => {
      mockPost.mockResolvedValue({ valid: true });

      await userApi.validateGoto('https%3A%2F%2Fexample.com');

      expect(mockPost).toHaveBeenCalledWith(
        expect.any(String),
        { goto: 'https://example.com' },
        expect.any(Object),
      );
    });
  });
});
