/**
 * User-related type definitions for OpenAM UI.
 * Covers user profile, authentication callbacks, self-service, and dashboard.
 */

// ---------------------------------------------------------------------------
// User Profile
// ---------------------------------------------------------------------------

export interface UserProfile {
  _id: string;
  uid: string;
  username: string;
  realm: string;
  givenName: string;
  sn: string;
  mail: string;
  telephoneNumber?: string;
  postalAddress?: string;
  roles: string[];
  kbaInfo: KBAInfo[];
  userPassword?: string;
  /** MVCC revision — present on read responses */
  rev?: string;
}

export interface UserProfileUpdate {
  givenName: string;
  sn: string;
  mail: string;
  postalAddress?: string;
  telephoneNumber?: string;
}

export interface ChangePasswordPayload {
  username: string;
  currentpassword: string;
  userpassword: string;
}

// ---------------------------------------------------------------------------
// Authentication Callbacks
// ---------------------------------------------------------------------------

/** Base callback shape returned by the authenticate endpoint. */
export interface AuthCallback {
  type: string;
  output: CallbackOutput[];
  input?: CallbackInput[];
}

export interface CallbackOutput {
  name: string;
  value: unknown;
}

export interface CallbackInput {
  name: string;
  value?: unknown;
}

export interface PasswordCallback extends AuthCallback {
  type: 'PasswordCallback';
  input: [{ name: 'password', value: '' }];
}

export interface TextInputCallback extends AuthCallback {
  type: 'TextInputCallback';
  input: [{ name: 'input', value: '' }];
}

export interface TextOutputCallback extends AuthCallback {
  type: 'TextOutputCallback';
  output: [
    { name: 'message', value: string },
    { name: 'messageType', value: number },  // 0 = text, 4 = script
  ];
}

export interface ConfirmationCallback extends AuthCallback {
  type: 'ConfirmationCallback';
  output: [
    { name: 'prompt', value: string },
    { name: 'options', value: string[] },
    { name: 'optionType', value: number }, // 0 = yes/no, 2 = radio, 3 = select
    { name: 'defaultOption', value: number },
    { name: 'value', value: boolean },
  ];
}

export interface ChoiceCallback extends AuthCallback {
  type: 'ChoiceCallback';
  output: [
    { name: 'prompt', value: string },
    { name: 'choices', value: string[] },
    { name: 'defaultChoice', value: number },
    { name: 'value', value: string },
  ];
}

export interface HiddenValueCallback extends AuthCallback {
  type: 'HiddenValueCallback';
  output: [
    { name: 'prompt', value: string },
    { name: 'value', value: string },
  ];
  input: [{ name: 'input', value: string }];
}

export interface RedirectCallback extends AuthCallback {
  type: 'RedirectCallback';
  output: [
    { name: 'redirectUrl', value: string },
    { name: 'trackingCookie', value: boolean },
    { name: 'waitForReturn', value: boolean },
    { name: 'waitTimeout', value: number },
  ];
}

export interface PollingWaitCallback extends AuthCallback {
  type: 'PollingWaitCallback';
  output: [
    { name: 'waitTime', value: number },
    { name: 'message', value: string },
  ];
}

export type LoginCallback =
  | PasswordCallback
  | TextInputCallback
  | TextOutputCallback
  | ConfirmationCallback
  | ChoiceCallback
  | HiddenValueCallback
  | RedirectCallback
  | PollingWaitCallback
  | AuthCallback; // fallback for unknown types

// ---------------------------------------------------------------------------
// Authentication Requirements (server response)
// ---------------------------------------------------------------------------

export interface AuthRequirements {
  authId?: string;
  tokenId?: string;
  realm?: string;
  stage?: string;
  callbacks?: LoginCallback[];
  detail?: {
    failureUrl?: string;
  };
}

// ---------------------------------------------------------------------------
// KBA (Knowledge-Based Authentication)
// ---------------------------------------------------------------------------

export interface KBAQuestion {
  questionId: string;
  question: string;
  answer: string;
}

export type KBAInfo = KBAQuestion[];

export interface KBAOptions {
  predefinedQuestions: string[];
}

// ---------------------------------------------------------------------------
// Self-Service Process
// ---------------------------------------------------------------------------

export interface SelfServiceStage {
  type: string;
  tag: string;
  callbacks: AuthCallback[];
}

export interface SelfServiceProcessState {
  token?: string;
  stage: SelfServiceStage;
  addRequirementsOutput?: string[];
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export interface TrustedDevice {
  _id: string;
  name: string;
  manufacturer?: string;
  model?: string;
  os?: string;
  osVersion?: string;
  dateRegistered: string;
  lastAccessed: string;
}

export interface OAuthToken {
  _id: string;
  clientId: string;
  type: string;
  scope: string[];
  tokenId: string;
  tokenName?: string;
  expiryTime: number;
  idleExpiryTime: number;
  uid?: string;
  realm?: string;
}

export interface DashboardApplication {
  id: string;
  name: string;
  description?: string;
  url?: string;
  icon?: string;
  [key: string]: unknown;
}

export interface OathDevice {
  _id: string;
  UUID: string;
  serialNumber?: string;
  deviceName?: string;
  dateCreated: string;
  lastUsed?: string;
}
