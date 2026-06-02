export interface AuthorizeError {
  uri?: string;
  message: string;
  description?: string;
}

export interface AuthorizeScope {
  name: string;
  values?: string | string[] | Record<string, string>;
}

export interface AuthorizeOAuth2Data {
  displayName: string;
  displayDescription?: string;
  displayScopes: AuthorizeScope[];
  displayClaims: AuthorizeScope[];
  formTarget: string;
  userName?: string;
  realm?: string;
  redirectUri?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  acr?: string;
  userCode?: string;
  responseType: string;
  clientId: string;
  csrf?: string;
  isSaveConsentEnabled?: boolean;
}

export interface AuthorizePageData {
  locale?: string;
  realm: string;
  baseUrl: string;
  oauth2Data?: AuthorizeOAuth2Data;
  error?: AuthorizeError;
  noScopes?: boolean;
  theme?: string;
}

declare global {
  interface Window {
    pageData: AuthorizePageData;
  }
}

export {};
