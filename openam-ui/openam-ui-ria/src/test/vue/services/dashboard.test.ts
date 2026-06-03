import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGet = vi.fn();
const mockPost = vi.fn();
const mockDelete = vi.fn();

vi.mock('@/services/api', () => {
  return {
    RestClient: class MockRestClient {
      get = mockGet;
      post = mockPost;
      put = vi.fn();
      patch = vi.fn();
      delete = mockDelete;
    },
  };
});

import { dashboardApi } from '@/services/dashboard';

describe('dashboard service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getTrustedDevices', () => {
    it('fetches trusted devices for user', async () => {
      const mockDevices = {
        result: [
          { _id: 'device-1', name: 'iPhone', dateRegistered: '2024-01-01' },
          { _id: 'device-2', name: 'Android', dateRegistered: '2024-01-02' },
        ],
      };
      mockGet.mockResolvedValue(mockDevices);

      const result = await dashboardApi.getTrustedDevices('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        '/users/testuser/devices/trusted/?_queryId=*',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Cache-Control': 'no-cache',
            'Accept-API-Version': expect.stringContaining('resource=1.0'),
          }),
        }),
      );
      expect(result).toEqual(mockDevices.result);
    });
  });

  describe('deleteTrustedDevice', () => {
    it('deletes a trusted device', async () => {
      mockDelete.mockResolvedValue(undefined);

      await dashboardApi.deleteTrustedDevice('testuser', 'device-123');

      expect(mockDelete).toHaveBeenCalledWith(
        '/users/testuser/devices/trusted/device-123',
        expect.any(Object),
      );
    });
  });

  describe('getOathDevices', () => {
    it('fetches OATH devices for user', async () => {
      const mockDevices = {
        result: [
          { _id: 'oath-1', UUID: 'uuid-1', deviceName: 'Authenticator' },
        ],
      };
      mockGet.mockResolvedValue(mockDevices);

      const result = await dashboardApi.getOathDevices('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        '/users/testuser/devices/2fa/oath?_queryFilter=true',
        expect.any(Object),
      );
      expect(result).toEqual(mockDevices.result);
    });
  });

  describe('deleteOathDevice', () => {
    it('deletes an OATH device by UUID', async () => {
      mockDelete.mockResolvedValue(undefined);

      await dashboardApi.deleteOathDevice('testuser', 'uuid-123');

      expect(mockDelete).toHaveBeenCalledWith(
        '/users/testuser/devices/2fa/oath/uuid-123',
        expect.any(Object),
      );
    });
  });

  describe('checkOathSkippable', () => {
    it('checks if OATH skip is enabled', async () => {
      mockPost.mockResolvedValue({ result: true });

      const result = await dashboardApi.checkOathSkippable('testuser');

      expect(mockPost).toHaveBeenCalledWith(
        '/users/testuser/devices/2fa/oath?_action=check',
        {},
        expect.any(Object),
      );
      expect(result).toBe(true);
    });
  });

  describe('setOathSkippable', () => {
    it('sets the OATH skip flag', async () => {
      mockPost.mockResolvedValue({});

      await dashboardApi.setOathSkippable('testuser', true);

      expect(mockPost).toHaveBeenCalledWith(
        '/users/testuser/devices/2fa/oath?_action=skip',
        { value: true },
        expect.any(Object),
      );
    });
  });

  describe('getMyApplications', () => {
    it('fetches assigned applications', async () => {
      const mockApps = {
        result: [
          { id: 'app-1', name: 'App 1', description: 'Test app' },
        ],
      };
      mockGet.mockResolvedValue(mockApps);

      const result = await dashboardApi.getMyApplications('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        '/users/testuser/oauth2/applications?_queryFilter=true',
        expect.any(Object),
      );
      expect(result).toEqual(mockApps.result);
    });
  });

  describe('revokeApplication', () => {
    it('revokes an application', async () => {
      mockDelete.mockResolvedValue(undefined);

      await dashboardApi.revokeApplication('testuser', 'app-123');

      expect(mockDelete).toHaveBeenCalledWith(
        '/users/testuser/oauth2/applications/app-123',
        expect.any(Object),
      );
    });
  });

  describe('getDashboardConfig', () => {
    it('fetches dashboard configuration', async () => {
      const mockConfig = { enabled: true };
      mockGet.mockResolvedValue(mockConfig);

      const result = await dashboardApi.getDashboardConfig();

      expect(mockGet).toHaveBeenCalledWith(
        '/dashboard/config',
        expect.any(Object),
      );
      expect(result).toEqual(mockConfig);
    });
  });
});
