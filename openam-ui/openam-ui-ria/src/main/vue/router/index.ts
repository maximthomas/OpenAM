import { createRouter, createWebHashHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';
import { createAuthGuard, createDefaultRouteGuard } from './guards';

// Layouts (eagerly imported — sidebar must render before child page)
import RealmLayout from '@/views/realm/RealmLayout.vue';
import ServerLayout from '@/views/server/ServerLayout.vue';
import ServerDefaultsLayout from '@/views/server/ServerDefaultsLayout.vue';
import LabelTreeLayout from '@/views/uma/LabelTreeLayout.vue';

// Error views (eagerly imported — small, shown immediately)
import NotFoundView from '@/views/errors/NotFoundView.vue';
import ForbiddenView from '@/views/errors/ForbiddenView.vue';

// Placeholder views — lazy-loaded (each is a tiny stub, but code-splitting is correct practice)
const DefaultView = () => import('@/views/common/DefaultView.vue');
const EnableCookiesView = () => import('@/views/common/EnableCookiesView.vue');

// User views
const ProfileView = () => import('@/views/user/ProfileView.vue');
const ForgotUsernameView = () => import('@/views/user/ForgotUsernameView.vue');
const PasswordResetView = () => import('@/views/user/PasswordResetView.vue');
const SelfRegistrationView = () => import('@/views/user/SelfRegistrationView.vue');
const ContinuePasswordResetView = () => import('@/views/user/ContinuePasswordResetView.vue');
const ContinueSelfRegisterView = () => import('@/views/user/ContinueSelfRegisterView.vue');
const LoginView = () => import('@/views/user/LoginView.vue');
const ConfirmLoginView = () => import('@/views/user/ConfirmLoginView.vue');
const LoggedOutView = () => import('@/views/user/LoggedOutView.vue');
const LoginFailureView = () => import('@/views/user/LoginFailureView.vue');
const SessionExpiredView = () => import('@/views/user/SessionExpiredView.vue');
const DashboardView = () => import('@/views/user/dashboard/DashboardView.vue');
const TokensView = () => import('@/views/user/oauth2/TokensView.vue');

// Admin - Realms
const ListRealmsView = () => import('@/views/admin/realms/ListRealmsView.vue');
const EditRealmView = () => import('@/views/admin/realms/EditRealmView.vue');
const RealmDashboardView = () => import('@/views/admin/realms/RealmDashboardView.vue');

// Admin - Authentication
const AuthenticationSettingsView = () => import('@/views/admin/authentication/SettingsView.vue');
const AuthenticationChainsView = () => import('@/views/admin/authentication/ChainsView.vue');
const EditChainView = () => import('@/views/admin/authentication/EditChainView.vue');
const AddChainView = () => import('@/views/admin/authentication/AddChainView.vue');
const AuthenticationModulesView = () => import('@/views/admin/authentication/ModulesView.vue');
const AddModuleView = () => import('@/views/admin/authentication/AddModuleView.vue');
const EditModuleView = () => import('@/views/admin/authentication/EditModuleView.vue');

// Admin - Services
const ServicesView = () => import('@/views/admin/services/ServicesView.vue');
const EditServiceView = () => import('@/views/admin/services/EditServiceView.vue');
const NewServiceView = () => import('@/views/admin/services/NewServiceView.vue');
const NewServiceSubSchemaView = () => import('@/views/admin/services/NewServiceSubSchemaView.vue');
const EditServiceSubSchemaView = () => import('@/views/admin/services/EditServiceSubSchemaView.vue');

// Admin - Sessions
const SessionsView = () => import('@/views/admin/sessions/SessionsView.vue');

// Admin - Authorization
const PolicySetsView = () => import('@/views/admin/authorization/PolicySetsView.vue');
const EditPolicySetView = () => import('@/views/admin/authorization/EditPolicySetView.vue');
const EditPolicyView = () => import('@/views/admin/authorization/EditPolicyView.vue');
const ResourceTypesView = () => import('@/views/admin/authorization/ResourceTypesView.vue');
const EditResourceTypeView = () => import('@/views/admin/authorization/EditResourceTypeView.vue');

// Admin - Scripts
const ScriptsView = () => import('@/views/admin/scripts/ScriptsView.vue');
const EditScriptView = () => import('@/views/admin/scripts/EditScriptView.vue');

// Admin - Applications
const SelectAgentView = () => import('@/views/admin/applications/SelectAgentView.vue');
const NewAgentView = () => import('@/views/admin/applications/NewAgentView.vue');

// Admin - API
const ListApiView = () => import('@/views/admin/api/ListApiView.vue');
const ApiDocView = () => import('@/views/admin/api/ApiDocView.vue');

// Admin - Configuration - Authentication
const ListAuthenticationView = () => import('@/views/admin/configuration/authentication/ListAuthenticationView.vue');
const EditGlobalAuthenticationView = () => import('@/views/admin/configuration/authentication/EditGlobalAuthenticationView.vue');

// Admin - Configuration - Global Services
const ListGlobalServicesView = () => import('@/views/admin/configuration/global-services/ListGlobalServicesView.vue');
const EditGlobalServiceView = () => import('@/views/admin/configuration/global-services/EditGlobalServiceView.vue');
const NewGlobalServiceSubSchemaView = () => import('@/views/admin/configuration/global-services/NewGlobalServiceSubSchemaView.vue');
const EditGlobalServiceSubSchemaView = () => import('@/views/admin/configuration/global-services/EditGlobalServiceSubSchemaView.vue');
const EditGlobalServiceSubSubSchemaView = () => import('@/views/admin/configuration/global-services/EditGlobalServiceSubSubSchemaView.vue');

// Admin - Deployment - Sites
const ListSitesView = () => import('@/views/admin/deployment/sites/ListSitesView.vue');
const EditSiteView = () => import('@/views/admin/deployment/sites/EditSiteView.vue');
const NewSiteView = () => import('@/views/admin/deployment/sites/NewSiteView.vue');

// Admin - Deployment - Servers
const ListServersView = () => import('@/views/admin/deployment/servers/ListServersView.vue');
const NewServerView = () => import('@/views/admin/deployment/servers/NewServerView.vue');
const EditServerView = () => import('@/views/admin/deployment/servers/EditServerView.vue');

// Admin - Server Defaults
const EditServerDefaultsView = () => import('@/views/admin/configuration/server-defaults/EditServerDefaultsView.vue');

// UMA - Resources
const MyResourcesPage = () => import('@/views/uma/resources/MyResourcesPage.vue');
const ResourcePage = () => import('@/views/uma/resources/ResourcePage.vue');
const SharedWithMePage = () => import('@/views/uma/resources/SharedWithMePage.vue');
const StarredPage = () => import('@/views/uma/resources/StarredPage.vue');
const MyLabelsPage = () => import('@/views/uma/resources/MyLabelsPage.vue');

// UMA - History
const ListHistory = () => import('@/views/uma/history/ListHistory.vue');

// UMA - Requests
const EditRequest = () => import('@/views/uma/requests/EditRequest.vue');
const ListRequest = () => import('@/views/uma/requests/ListRequest.vue');

// UMA - Share
const BaseShare = () => import('@/views/uma/share/BaseShare.vue');

const authGuard = createAuthGuard();
const defaultRouteGuard = createDefaultRouteGuard();

const routes: RouteRecordRaw[] = [
  // ── Default route ──────────────────────────────────────────────
  {
    path: '/',
    name: 'default',
    beforeEnter: defaultRouteGuard,
    component: DefaultView,
  },

  // ── Login ─────────────────────────────────────────────────────
  {
    path: '/login',
    name: 'login',
    component: LoginView,
  },

  // ── Logout (standalone service handles it) ────────────────────
  {
    path: '/logout',
    name: 'logout',
    beforeEnter() {
      // logout() is called from AppHeader; this route is a fallback
      window.location.href = '/';
    },
    component: DefaultView,
  },

  // ── User routes ───────────────────────────────────────────────
  {
    path: '/profile/:pathMatch(.*)*',
    name: 'profile',
    component: ProfileView,
    meta: { roles: ['ui-self-service-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },
  {
    path: '/dashboard',
    name: 'dashboard',
    component: DashboardView,
    meta: { roles: ['ui-self-service-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },
  {
    path: '/oauth2/tokens',
    name: 'oauth2Tokens',
    component: TokensView,
    meta: { roles: ['ui-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },

  // ── Anonymous / self-service routes (Backbone) ────────────────
  {
    path: '/forgotUsername/:realm?/:additionalParams?',
    name: 'forgotUsername',
    component: ForgotUsernameView,
  },
  {
    path: '/passwordReset/:realm?/:additionalParams?',
    name: 'passwordReset',
    component: PasswordResetView,
  },
  {
    path: '/register/:realm?/:additionalParams?',
    name: 'selfRegistration',
    component: SelfRegistrationView,
  },
  {
    path: '/continuePasswordReset/:realm/:additionalParams?',
    name: 'continuePasswordReset',
    component: ContinuePasswordResetView,
  },
  {
    path: '/continueRegister/:realm/:additionalParams?',
    name: 'continueSelfRegister',
    component: ContinueSelfRegisterView,
  },
  {
    path: '/confirmLogin',
    name: 'confirmLogin',
    component: ConfirmLoginView,
  },
  {
    path: '/loggedOut/:realm?/:additionalParams?',
    name: 'loggedOut',
    component: LoggedOutView,
  },
  {
    path: '/failedLogin/:realm?/:additionalParams?',
    name: 'loginFailure',
    component: LoginFailureView,
  },
  {
    path: '/sessionExpired/:realm?/:additionalParams?',
    name: 'sessionExpired',
    component: SessionExpiredView,
  },

  // ── Enable cookies ────────────────────────────────────────────
  {
    path: '/enableCookies',
    name: 'enableCookies',
    component: EnableCookiesView,
  },

  // ── 403 Forbidden ─────────────────────────────────────────────
  {
    path: '/403',
    name: '403',
    component: ForbiddenView,
  },

  // ── Realm routes (scoped) ─────────────────────────────────────
  {
    path: '/realms',
    name: 'realms',
    component: ListRealmsView,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/realms/new',
    name: 'realmNew',
    component: EditRealmView,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/realms/:realmPath/edit',
    name: 'realmEdit',
    component: EditRealmView,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },

  // ── Realm-scoped child routes (nested under RealmLayout) ──────
  {
    path: '/realms/:realmPath',
    component: RealmLayout,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
    children: [
      {
        path: '',
        redirect: { name: 'realmsDashboard' },
      },
      {
        path: 'dashboard',
        name: 'realmsDashboard',
        component: RealmDashboardView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-settings',
        name: 'realmsAuthenticationSettings',
        component: AuthenticationSettingsView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-chains',
        name: 'realmsAuthenticationChains',
        component: AuthenticationChainsView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-chains/edit/:chainName',
        name: 'realmsAuthenticationChainEdit',
        component: EditChainView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-chains/new',
        name: 'realmsAuthenticationChainNew',
        component: AddChainView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-modules',
        name: 'realmsAuthenticationModules',
        component: AuthenticationModulesView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-modules/new',
        name: 'realmsAuthenticationModuleNew',
        component: AddModuleView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authentication-modules/:moduleName/edit/:moduleType',
        name: 'realmsAuthenticationModuleEdit',
        component: EditModuleView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'services',
        name: 'realmsServices',
        component: ServicesView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'services/edit/:serviceName',
        name: 'realmsServiceEdit',
        component: EditServiceView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'services/new',
        name: 'realmsServiceNew',
        component: NewServiceView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'services/edit/:serviceName/:subSchemaId/new',
        name: 'realmsServiceSubSchemaNew',
        component: NewServiceSubSchemaView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'services/edit/:serviceName/:subSchemaId/edit/:subSubSchemaId',
        name: 'realmsServiceSubSchemaEdit',
        component: EditServiceSubSchemaView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'sessions',
        name: 'realmsSessions',
        component: SessionsView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-policySets',
        name: 'realmsPolicySets',
        component: PolicySetsView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-policySets/edit/:policySetName',
        name: 'realmsPolicySetEdit',
        component: EditPolicySetView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-policySets/new',
        name: 'realmsPolicySetNew',
        component: EditPolicySetView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-policySets/edit/:policySetName/policies/new',
        name: 'realmsPolicyNew',
        component: EditPolicyView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-policySets/edit/:policySetName/policies/edit/:policyId',
        name: 'realmsPolicyEdit',
        component: EditPolicyView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-resourceTypes',
        name: 'realmsResourceTypes',
        component: ResourceTypesView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-resourceTypes/edit/:resourceTypeId',
        name: 'realmsResourceTypeEdit',
        component: EditResourceTypeView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'authorization-resourceTypes/new',
        name: 'realmsResourceTypeNew',
        component: EditResourceTypeView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'scripts',
        name: 'realmsScripts',
        component: ScriptsView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'scripts/edit/:scriptId',
        name: 'realmsScriptEdit',
        component: EditScriptView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'scripts/new',
        name: 'realmsScriptNew',
        component: EditScriptView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'applications-agents/new',
        name: 'realmsApplicationsAgentsSelection',
        component: SelectAgentView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
      {
        path: 'applications-agents/new/:agentType',
        name: 'realmsApplicationsAgentsNew',
        component: NewAgentView,
        meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
      },
    ],
  },

  // ── Global admin routes ───────────────────────────────────────
  {
    path: '/configure/authentication',
    name: 'listAuthenticationSettings',
    component: ListAuthenticationView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/configure/authentication/:id',
    name: 'editAuthenticationSettings',
    component: EditGlobalAuthenticationView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/configure/global-services',
    name: 'listGlobalServices',
    component: ListGlobalServicesView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/configure/global-services/:id',
    name: 'editGlobalService',
    component: EditGlobalServiceView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/configure/global-services/:serviceId/:subSchemaId/new',
    name: 'globalServiceSubSchemaNew',
    component: NewGlobalServiceSubSchemaView,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/configure/global-services/:serviceId/:subSchemaId/edit/:subSubSchemaId',
    name: 'globalServiceSubSchemaEdit',
    component: EditGlobalServiceSubSchemaView,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/configure/global-services/:serviceId/:subSchemaId/edit/:subSubSchemaId/:subSubSubSchemaId/edit/:subSubSubSubSchemaId',
    name: 'globalServiceSubSubSchemaEdit',
    component: EditGlobalServiceSubSubSchemaView,
    meta: { roles: ['ui-realm-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/deployment/sites',
    name: 'listSites',
    component: ListSitesView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/deployment/sites/edit/:siteId',
    name: 'editSite',
    component: EditSiteView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/deployment/sites/new',
    name: 'newSite',
    component: NewSiteView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/deployment/servers',
    name: 'listServers',
    component: ListServersView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/deployment/servers/new',
    name: 'newServer',
    component: NewServerView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/deployment/servers/clone/:serverName',
    name: 'cloneServer',
    component: NewServerView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },

  // ── Server edit (nested under ServerLayout) ───────────────────
  {
    path: '/deployment/servers/:serverName',
    component: ServerLayout,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
    children: [
      {
        path: 'general',
        name: 'editServerGeneral',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'security',
        name: 'editServerSecurity',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'session',
        name: 'editServerSession',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'sdk',
        name: 'editServerSdk',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'cts',
        name: 'editServerCts',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'uma',
        name: 'editServerUma',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'advanced',
        name: 'editServerAdvanced',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'directoryConfiguration',
        name: 'editServerDirectoryConfiguration',
        component: EditServerView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
    ],
  },

  // ── Server defaults (nested under ServerDefaultsLayout) ───────
  {
    path: '/configure/server-defaults',
    component: ServerDefaultsLayout,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
    children: [
      {
        path: '',
        redirect: { name: 'editServerDefaultsGeneral' },
      },
      {
        path: 'general',
        name: 'editServerDefaultsGeneral',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'security',
        name: 'editServerDefaultsSecurity',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'session',
        name: 'editServerDefaultsSession',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'sdk',
        name: 'editServerDefaultsSdk',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'cts',
        name: 'editServerDefaultsCts',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'uma',
        name: 'editServerDefaultsUma',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
      {
        path: 'advanced',
        name: 'editServerDefaultsAdvanced',
        component: EditServerDefaultsView,
        meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
      },
    ],
  },

  // ── API routes ────────────────────────────────────────────────
  {
    path: '/api/explorer',
    name: 'apiExplorerView',
    component: ListApiView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },
  {
    path: '/api/doc',
    name: 'apiDocView',
    component: ApiDocView,
    meta: { roles: ['ui-global-admin'], navGroup: 'admin' },
    beforeEnter: authGuard,
  },

  // ── UMA routes (nested under LabelTreeLayout) ─────────────────
  {
    path: '/uma/resources',
    component: LabelTreeLayout,
    meta: { roles: ['ui-uma-user'], navGroup: 'user' },
    beforeEnter: authGuard,
    children: [
      {
        path: '',
        redirect: { name: 'umaResourcesMyResources' },
      },
      {
        path: 'myresources',
        name: 'umaResourcesMyResources',
        component: MyResourcesPage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'myresources/:resourceType/:resourceId',
        name: 'umaResourcesMyResourcesResource',
        component: ResourcePage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'sharedwithme',
        name: 'umaResourcesSharedWithMe',
        component: SharedWithMePage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'sharedwithme/:resourceType',
        name: 'umaResourcesSharedWithMeResource',
        component: ResourcePage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'starred',
        name: 'umaResourcesStarred',
        component: StarredPage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'starred/:resourceType',
        name: 'umaResourcesStarredResource',
        component: ResourcePage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'mylabels/:labelId',
        name: 'umaResourcesMyLabels',
        component: MyLabelsPage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
      {
        path: 'mylabels/:labelId/:resourceType/:resourceId',
        name: 'umaResourcesMyLabelsResource',
        component: ResourcePage,
        meta: { roles: ['ui-uma-user'], navGroup: 'user' },
      },
    ],
  },
  {
    path: '/uma/history',
    name: 'umaHistory',
    component: ListHistory,
    meta: { roles: ['ui-uma-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },
  {
    path: '/uma/requests',
    name: 'umaRequestList',
    component: ListRequest,
    meta: { roles: ['ui-uma-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },
  {
    path: '/uma/requests/:requestId',
    name: 'umaRequestEdit',
    component: EditRequest,
    meta: { roles: ['ui-uma-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },
  {
    path: '/uma/share/:resourceId',
    name: 'umaBaseShare',
    component: BaseShare,
    meta: { roles: ['ui-uma-user'], navGroup: 'user' },
    beforeEnter: authGuard,
  },

  // ── 404 catch-all (must be last) ──────────────────────────────
  {
    path: '/:pathMatch(.*)*',
    name: '404',
    component: NotFoundView,
  },
];

const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

export default router;
