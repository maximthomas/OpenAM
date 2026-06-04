import type { NavigationGuardNext, RouteLocationNormalized } from 'vue-router';
import { useAuth } from '@/composables/useAuth';

export function createAuthGuard() {
  return (
    to: RouteLocationNormalized,
    _from: RouteLocationNormalized,
    next: NavigationGuardNext,
  ) => {
    const { isAuthenticated, hasAnyRole, initialized } = useAuth();

    if (!initialized.value) {
      next({ name: 'login' });
      return;
    }

    if (!isAuthenticated.value) {
      next({ name: 'login' });
      return;
    }

    const requiredRoles = to.meta.roles;
    if (requiredRoles && requiredRoles.length > 0 && !hasAnyRole(requiredRoles)) {
      next({ name: '403' });
      return;
    }

    next();
  };
}

export function createDefaultRouteGuard() {
  return (
    to: RouteLocationNormalized,
    _from: RouteLocationNormalized,
    next: NavigationGuardNext,
  ) => {
    const { isAuthenticated, hasRole, initialized } = useAuth();

    if (!initialized.value || !isAuthenticated.value) {
      next({ name: 'login' });
      return;
    }

    if (hasRole('ui-realm-admin') || hasRole('ui-global-admin')) {
      next({ name: 'realms' });
    } else {
      next({ name: 'profile' });
    }
  };
}
