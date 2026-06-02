import { reactive, computed } from 'vue';

interface LoggedUser {
  username: string;
  realm: string;
  roles: string[];
}

interface AuthState {
  loggedUser: LoggedUser | null;
  initialized: boolean;
}

const state = reactive<AuthState>({
  loggedUser: null,
  initialized: false,
});

export function useAuth() {
  const isAuthenticated = computed(() => state.loggedUser !== null);

  function hasRole(role: string): boolean {
    return state.loggedUser?.roles.includes(role) ?? false;
  }

  function hasAnyRole(roles: string[]): boolean {
    return roles.some((role) => hasRole(role));
  }

  function hasAllRoles(roles: string[]): boolean {
    return roles.every((role) => hasRole(role));
  }

  function getRealm(): string {
    return state.loggedUser?.realm ?? '/';
  }

  function getUser(): LoggedUser | null {
    return state.loggedUser;
  }

  function setUser(user: LoggedUser | null): void {
    state.loggedUser = user;
  }

  function setInitialized(value: boolean): void {
    state.initialized = value;
  }

  function reset(): void {
    state.loggedUser = null;
    state.initialized = false;
  }

  return {
    loggedUser: computed(() => state.loggedUser),
    initialized: computed(() => state.initialized),
    isAuthenticated,
    hasRole,
    hasAnyRole,
    hasAllRoles,
    getRealm,
    getUser,
    setUser,
    setInitialized,
    reset,
  };
}
