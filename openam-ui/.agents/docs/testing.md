# Testing

## Commands

| Layer | Tool | Command |
|---|---|---|
| openam-ui-ria (Vue) | Vitest | `cd openam-ui-ria && npx vitest run` |
| openam-ui-ria (Vue, watch) | Vitest | `cd openam-ui-ria && npx vitest` |
| openam-ui-ria (Backbone) | Karma + QUnit | `npx grunt karma:unit` (watch) or `mvn test -pl openam-ui/openam-ui-ria` |
| openam-ui-ria full build + test | Grunt `karma:build` | Triggered automatically by `mvn package` |
| openam-ui-api | npm test | `cd openam-ui/openam-ui-api && npm test` |
| Type checking | vue-tsc | `cd openam-ui-ria && npx vue-tsc --noEmit` |

## File Locations

- **Vitest tests:** `openam-ui-ria/src/test/vue/`
- **Karma tests:** `openam-ui-ria/src/test/` (old Backbone)
- **Vitest config:** `openam-ui-ria/vitest.config.ts` (happy-dom environment)

## Writing Tests

### Mock pattern for services

Services use `RestClient` from `@/services/api`. Mock it with a class-based mock:

```typescript
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

import { myService } from '@/services/myService';

describe('myService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches data', async () => {
    mockGet.mockResolvedValue({ result: [] });
    const result = await myService.getData('user1');
    expect(mockGet).toHaveBeenCalledWith(
      expect.stringContaining('/users/user1'),
      expect.any(Object),
    );
  });
});
```

### Import order

1. `vi.mock()` calls first (hoisted by vitest)
2. Import the module under test after the mock
3. Use `beforeEach(() => vi.clearAllMocks())` to reset state
