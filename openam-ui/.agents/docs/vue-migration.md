# Vue Migration Guide

## Realm URL Convention

All realm-scoped endpoints use `/json/{realm}/endpoint` format:

```
/json/root/authenticate                    # root realm
/json/b2c/clients/authenticate            # nested realm
/json/authenticate                         # no realm (default)
```

Realm is passed as `root` or `b2c/clients` — **no leading slash, no `/realms/` prefix**.

## Service Patterns

Services live in `src/main/vue/services/`. They use `RestClient` from `@/services/api`.

```typescript
import { RestClient } from './api';
import { Constants } from './constants';

function buildBaseUrl(): string {
  return `${Constants.host}/${Constants.context}/json`;
}

export const myApi = {
  getData(realm: string, id: string): Promise<MyType> {
    const client = new RestClient(buildBaseUrl());
    const realmSegment = realm ? `/${realm}` : '';
    return client.get<MyType>(
      `${realmSegment}/endpoint/${encodeURIComponent(id)}`,
      { headers: { 'Accept-API-Version': 'protocol=1.0,resource=1.0' } },
    );
  },
};
```

**Rules:**
- No `errorsHandlers` suppression — all errors propagate to callers
- Callers handle errors via `useAlert().danger(response)` extracting `response.responseJSON.message`
- Always set `Accept-API-Version` header
- `encodeURIComponent()` on user-supplied IDs in URL paths
- Realm prepended as `/${realm}` before endpoint (produces `/json/{realm}/endpoint`)

## Existing Services

| Service | File | Endpoints |
|---|---|---|
| User | `services/user.ts` | `GET /json/{realm}/users/{id}`, `PUT /json/{realm}/users/{id}`, `POST /json/{realm}/users/{id}?_action=changePassword`, `POST /json/{realm}/users?_action=validateGoto` |
| AuthN | `services/authN.ts` | `POST /json/{realm}/authenticate`, `POST /json/{realm}/users?_action=validateGoto`, `GET /json/serverinfo/*` |
| Session | `services/session.ts` | `POST /json/sessions?_action=getSessionInfo`, `POST /json/sessions/{id}?_action=destroy`, `GET /json/sessions/{id}/properties` |
| Token | `services/token.ts` | `GET /json/frrest/oauth2/token/?_queryid=*`, `DELETE /json/frrest/oauth2/token/{id}`, `GET /json/frrest/oauth2/token/{id}` |
| Dashboard | `services/dashboard.ts` | `GET /json/{realm}/users/{id}/devices/trusted/`, `DELETE /json/{realm}/users/{id}/devices/trusted/{id}`, `GET /json/{realm}/users/{id}/devices/2fa/oath`, `GET /json/{realm}/users/{id}/oauth2/applications` |
| UMA | `services/uma.ts` | `GET /json/serverinfo/uma`, `GET /json/{realm}/users/{id}/oauth2/resources/sets`, `POST ...?_action=create`, `DELETE .../{id}`, `GET .../labels`, `POST .../pendingrequests/{id}?_action=approve`, `GET .../history` |
| SelfService | `services/selfService.ts` | `POST /json/{realm}/selfservice/forgottenPassword`, `POST /json/{realm}/selfservice/userRegistration`, `POST /json/{realm}/users?_action=validateGoto` |
| KBA | `services/kba.ts` | `GET /json/{realm}/selfservice/kbaOptions`, `POST /json/{realm}/selfservice/forgottenPassword`, `POST /json/users/{id}?_action=validateKbaAnswers`, `GET /json/users/{id}/kbaInfo` |
| Logout | `services/logout.ts` | `POST /json/realms/root/auth/logout` |
| OAuth2 | `services/oauth2.ts` | `GET /json/serverinfo/*` |

## Existing Types

| File | Key types |
|---|---|
| `types/user.d.ts` | `UserProfile`, `AuthRequirements`, `LoginCallback` (10 variants), `KBAInfo`, `SelfServiceProcessState`, `TrustedDevice`, `OAuthToken`, `DashboardApplication`, `OathDevice` |
| `types/uma.d.ts` | `UMAResourceSet`, `UMALabel`, `UMARequest`, `UMAHistoryEntry`, `UMAConfig`, `PaginatedResponse<T>`, `PaginationParams` |
| `types/router.d.ts` | `RouteMeta` (roles, navGroup, view) |
| `types/device.d.ts` | `DevicePageData` |
| `types/authorize.d.ts` | `AuthorizePageData` |

## Composables

| Composable | File | Purpose |
|---|---|---|
| `useAuth` | `composables/useAuth.ts` | Reactive auth state: `loggedUser`, `isAuthenticated`, `hasRole()`, `hasAnyRole()`, `getRealm()` |
| `useAlert` | `composables/useAlert.ts` | Alert queue: `success()`, `info()`, `warning()`, `danger(response)`, `dismiss()` |
| `useDialog` | `composables/useDialog.ts` | Promise-based confirm/cancel: `confirm(message)` |
| `useRealm` | `composables/useRealm.ts` | Decodes `%2F`-encoded realmPath from URL param |

## Vue SFC Conventions

- `<script lang="ts">` — TypeScript in all components
- Bootstrap 3 classes used as-is (no component library)
- `<style scoped>` for component-specific styles
- Global LESS entry points preserved for theme switching
- `v-model` with reactive form objects (replaces form2js)
- `defineExpose()` for parent component interaction (matches legacy Backbone API)
