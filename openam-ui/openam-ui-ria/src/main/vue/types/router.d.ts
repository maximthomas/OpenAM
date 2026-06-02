import 'vue-router';

declare module 'vue-router' {
  interface RouteMeta {
    roles?: string[];
    navGroup?: 'admin' | 'user';
    view?: string;
  }
}
