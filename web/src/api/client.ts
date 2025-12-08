import axios, { AxiosError, AxiosRequestConfig } from 'axios';

export const baseURL = '/api';

export interface Entity {
  id: string;
  created_at: string;
  updated_at: string;
}

export interface BaseResponse<T> {
  code: string;
  data: T;
  err?: string;
}

export interface PaginationResponse<T extends Entity> extends BaseResponse<T[]> {
  total: number;
  current: number;
  page_size: number;
}

export interface PaginationRequest {
  current: number;
  page_size: number;
}

const client = axios.create({
  baseURL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export class ApiError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

// Request interceptor
client.interceptors.request.use(
  (config) => {
    // Get token from localStorage
    const token = localStorage.getItem('token');
    if (token) {
      // Ensure headers object exists
      config.headers = config.headers || {};
      // Set Authorization header
      config.headers.Authorization = `Bearer ${token}`;
    }
    const i18nextLng = localStorage.getItem('i18nextLng');
    if (i18nextLng) {
      config.headers['Accept-Language'] = i18nextLng;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);


// Response interceptor
client.interceptors.response.use(
  (response) => {
    // Check for new format response
    const data = response.data;
    if (data && data.code !== undefined) {
      // If request is successful (code is "0"), return data field content
      if (data.code === "0") {
        // If it's paginated data, attach pagination information
        if (data.total !== undefined && data.current !== undefined && data.page_size !== undefined) {
          return {
            data: data.data,
            total: data.total,
            current: data.current,
            page_size: data.page_size
          };
        }
        // Return data content
        return data.data;
      }
      // If it's an error response (code is not "0"), throw an error
      else {
        return Promise.reject(data || "Unknown error");
      }
    }
    // Compatible with old format
    return response.data;
  },
  (error: AxiosError) => {
    // Handle 401 Unauthorized error
    if (error.response?.status === 401 && window.location.pathname !== '/console/login') {
      // Clear token
      localStorage.removeItem('token');
      // Clear Authorization header
      delete client.defaults.headers.common['Authorization'];
      // Redirect to login page
      window.location.href = '/console/login?redirect=' + encodeURIComponent(window.location.href);
    }
    // Extract error message
    const errorResponse = error.response?.data as BaseResponse<any>;
    let errorMessage = new ApiError(errorResponse.code || error.response?.status.toString() || '500', error.message);
    if (errorResponse) {
      if (errorResponse.code === "E50039") {
        // LDAP not enabled, goto settings page
        window.location.href = '/system/settings#ldap';
        return;
      } else if (errorResponse.err) {
        // New format error
        errorMessage = new ApiError(errorResponse.code, errorResponse.err);
      } else if ((errorResponse as any).error) {
        // Old format error
        errorMessage = new ApiError(errorResponse.code, (errorResponse as any).error);
      }
    }
    return Promise.reject(errorMessage);
  }
);

export interface ApiResponse<T> {
  code: string;
  data: T;
  err?: string;
  total?: number;
  current?: number;
  pageSize?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  current: number;
  pageSize: number;
}

export const apiGet = async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
  return client.get<T, T>(url, config);
};

export const apiPost = async <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> => {
  return client.post<T, T>(url, data, config);
};

export const apiPut = async <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> => {
  return client.put<T, T>(url, data, config);
};

export const apiDelete = async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
  return client.delete<T, T>(url, config);
};

export default client; 