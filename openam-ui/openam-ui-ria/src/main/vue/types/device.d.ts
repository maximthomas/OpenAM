export interface DevicePageData {
  locale?: string;
  errorCode?: string;
  realm: string;
  baseUrl: string;
  done?: boolean;
  theme?: string;
}

declare global {
  interface Window {
    pageData: DevicePageData;
  }
}

export {};
