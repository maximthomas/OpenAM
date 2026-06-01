import axios from 'axios';
import { Constants } from './constants';
import { config } from './config';
import { getCurrentLocale } from './i18n';
import { events } from './events';

export interface RestClientOptions {
  headers?: Record<string, string>;
  errorsHandlers?: Record<string, unknown>;
}

interface ErrorResponse {
  status: number;
  data?: { error?: string; message?: string; code?: number };
}

function matchError(error: ErrorResponse, handlers?: Record<string, unknown>): boolean {
  if (!handlers) return false;
  for (const handler of Object.values(handlers)) {
    const h = handler as Record<string, unknown>;
    if (h.status !== undefined && Number(error.status) === Number(h.status)) {
      return true;
    }
    if (h.field !== undefined && h.value !== undefined && (error as unknown as Record<string, unknown>)[h.field as string] === h.value) {
      return true;
    }
  }
  return false;
}

function buildHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Requested-With': 'XMLHttpRequest',
    'Cache-Control': 'no-cache',
  };
  const locale = getCurrentLocale();
  if (locale) {
    headers['Accept-Language'] = locale;
  }
  return { ...headers, ...extra };
}

export class RestClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async request<T = unknown>(
    method: string,
    url: string,
    data?: unknown,
    options?: RestClientOptions,
  ): Promise<T> {
    const fullUrl = this.baseUrl + url;
    const headers = buildHeaders(options?.headers);

    try {
      const response = await axios.request<T>({
        method,
        url: fullUrl,
        data,
        headers,
        withCredentials: true,
      });
      return response.data;
    } catch (err: unknown) {
      const axiosErr = err as { response?: { status: number; data?: unknown }; status?: number };
      const status = axiosErr.response?.status ?? axiosErr.status ?? 0;

      if (status === 401 && !matchError({ status } as ErrorResponse, options?.errorsHandlers)) {
        events.emit(Constants.EVENT_SHOW_LOGIN_DIALOG, {
          authenticatedCallback: () => this.request<T>(method, url, data, options),
        });
      }

      throw err;
    }
  }

  get<T = unknown>(url: string, options?: RestClientOptions): Promise<T> {
    return this.request<T>('GET', url, undefined, options);
  }

  post<T = unknown>(url: string, data?: unknown, options?: RestClientOptions): Promise<T> {
    return this.request<T>('POST', url, data, options);
  }

  put<T = unknown>(url: string, data?: unknown, options?: RestClientOptions): Promise<T> {
    return this.request<T>('PUT', url, data, options);
  }

  patch<T = unknown>(url: string, data?: unknown, options?: RestClientOptions): Promise<T> {
    return this.request<T>('PATCH', url, data, options);
  }

  delete<T = unknown>(url: string, options?: RestClientOptions): Promise<T> {
    return this.request<T>('DELETE', url, undefined, options);
  }

  patchDifferences<T extends Record<string, unknown>>(
    queryParameters: { id: string; rev: string },
    oldObject: T,
    newObject: T,
    options?: RestClientOptions,
  ): Promise<unknown> {
    const differences = getDifferences(oldObject, newObject);
    if (differences.length === 0) {
      return Promise.resolve();
    }
    const patchData = differences.map((d) => ({
      ...d,
      field: d.field.startsWith('/') ? d.field : `/${d.field}`,
    }));
    return this.patch(
      `/${queryParameters.id}`,
      patchData,
      {
        ...options,
        headers: {
          ...options?.headers,
          'If-Match': `"${queryParameters.rev}"`,
        },
      },
    );
  }
}

export interface PatchOperation {
  operation: string;
  field: string;
  value: unknown;
}

export function getDifferences<T extends Record<string, unknown>>(
  oldObject: T,
  newObject: T,
  method = 'replace',
): PatchOperation[] {
  const result: PatchOperation[] = [];
  for (const field of Object.keys(newObject)) {
    const newValue = newObject[field];
    const oldValue = oldObject[field];
    if (newValue !== '' || oldValue) {
      if (JSON.stringify(newValue) !== JSON.stringify(oldValue)) {
        result.push({ operation: method, field, value: newValue });
      }
    }
  }
  return result;
}
