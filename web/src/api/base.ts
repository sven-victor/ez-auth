import { apiGet, apiPost } from './client';

// Get current user information
export const getCurrentUser = async (): Promise<API.User> => {
  return apiGet<API.User>(`/authorization/profile`);
};

// User logout
export const logout = async (): Promise<void> => {
  return apiPost<void>(`/authorization/auth/logout`);
};

// Get navigation bar
export const getNavigation = async (): Promise<API.Navigation[]> => {
  return apiGet<API.Navigation[]>(`/system/navigation`);
};

// Upload file
export const uploadFile = async (file: File, fileType: string, access: 'private' | 'public' | 'owner' = 'private'): Promise<API.File[]> => {
  const formData = new FormData();
  formData.append(file.name ?? 'file', file);
  formData.append('access', access);
  formData.append('type', fileType);
  return apiPost<API.File[]>(`/files`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

// Get file
export const getFile = async (id: string): Promise<string> => {
  return apiGet<string>(`/files/${id}`);
};

// Get file list
export const getFileList = async (current?: number, pageSize?: number, fileType?: string, search?: string): Promise<API.File[]> => {
  return apiGet<API.File[]>(`/files`, {
    params: {
      current,
      page_size: pageSize,
      search,
      type: fileType,
    },
  });
};