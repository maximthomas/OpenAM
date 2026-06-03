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

import { kbaApi } from '@/services/kba';

describe('kba service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getPredefinedQuestions', () => {
    it('fetches predefined KBA questions', async () => {
      const mockQuestions = {
        predefinedQuestions: [
          'What is your mother\'s maiden name?',
          'What was the name of your first pet?',
        ],
      };
      mockGet.mockResolvedValue(mockQuestions);

      const result = await kbaApi.getPredefinedQuestions('/realms/root');

      expect(mockGet).toHaveBeenCalledWith(
        '/selfservice/kbaOptions/realms/root',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Accept-API-Version': expect.stringContaining('resource=1.0'),
          }),
        }),
      );
      expect(result).toEqual(mockQuestions.predefinedQuestions);
    });

    it('handles empty realm', async () => {
      mockGet.mockResolvedValue({ predefinedQuestions: [] });

      const result = await kbaApi.getPredefinedQuestions('');

      expect(mockGet).toHaveBeenCalledWith(
        '/selfservice/kbaOptions',
        expect.any(Object),
      );
      expect(result).toEqual([]);
    });
  });

  describe('submitKbaAnswers', () => {
    it('submits KBA answers for self-service process', async () => {
      mockPost.mockResolvedValue({});

      const kbaInfo = [
        { questionId: 'q1', question: 'Maiden name?', answer: 'Smith' },
      ];

      await kbaApi.submitKbaAnswers(
        'selfservice/forgottenPassword',
        '/realms/root',
        'token-123',
        kbaInfo,
      );

      expect(mockPost).toHaveBeenCalledWith(
        '/selfservice/forgottenPassword/realms/root',
        { token: 'token-123', kbaInfo },
        expect.any(Object),
      );
    });
  });

  describe('validateKbaAnswers', () => {
    it('validates KBA answers for a user', async () => {
      mockPost.mockResolvedValue({ valid: true });

      const kbaInfo = [
        { questionId: 'q1', question: 'Maiden name?', answer: 'Smith' },
      ];

      const result = await kbaApi.validateKbaAnswers('testuser', kbaInfo);

      expect(mockPost).toHaveBeenCalledWith(
        '/users/testuser?_action=validateKbaAnswers',
        { kbaInfo },
        expect.any(Object),
      );
      expect(result).toEqual({ valid: true });
    });
  });

  describe('getUserKbaInfo', () => {
    it('fetches KBA info for a user', async () => {
      const mockKbaInfo = [
        { questionId: 'q1', question: 'Maiden name?', answer: '***' },
      ];
      mockGet.mockResolvedValue(mockKbaInfo);

      const result = await kbaApi.getUserKbaInfo('testuser');

      expect(mockGet).toHaveBeenCalledWith(
        '/users/testuser/kbaInfo',
        expect.any(Object),
      );
      expect(result).toEqual(mockKbaInfo);
    });
  });

  describe('updateUserKbaInfo', () => {
    it('updates KBA info for a user', async () => {
      mockPost.mockResolvedValue({});

      const kbaInfo = [
        { questionId: 'q1', question: 'Maiden name?', answer: 'Smith' },
        { questionId: 'q2', question: 'First pet?', answer: 'Fluffy' },
      ];

      await kbaApi.updateUserKbaInfo('testuser', kbaInfo);

      expect(mockPost).toHaveBeenCalledWith(
        '/users/testuser?_action=updateKbaInfo',
        { kbaInfo },
        expect.any(Object),
      );
    });
  });
});
