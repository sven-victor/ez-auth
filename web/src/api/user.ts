import { apiGet, apiPost, apiPut, apiDelete } from './client';
import type { UserCreateRequest, UserUpdateRequest, UserListResponse } from '@/types/user';

// Get user list
export const getUsers = async (source?: string, keywords?: string, status?: string, current?: number, pageSize?: number): Promise<UserListResponse> => {
  return apiGet<UserListResponse>('/users', {
    params: { keywords, status, current, page_size: pageSize, source },
  });
};

// Get user details
export const getUser = async (id: string): Promise<API.User> => {
  return apiGet<API.User>(`/users/${id}`);
};

// Create user
export const createUser = async (data: UserCreateRequest,): Promise<API.User> => {
  return apiPost<API.User>('/users', data);
};

// Update user
export const updateUser = async (id: string, data: UserUpdateRequest): Promise<API.User> => {
  return apiPut<API.User>(`/users/${id}`, data);
};

// Delete user
export const deleteUser = async (id: string): Promise<void> => {
  return apiDelete(`/users/${id}`);
};

// Reset user password
export const resetUserPassword = async (id: string): Promise<{ new_password: string }> => {
  return apiPost<{ new_password: string }>(`/users/${id}/reset-password`);
};

// Get LDAP users
export const getLdapUsers = async (skipExisting: boolean = false): Promise<API.User[]> => {
  return apiGet<API.User[]>(`/users/ldap-users`, { params: { skip_existing: skipExisting } });
};


// Restore user
export const restoreUser = async (id: string): Promise<void> => {
  return apiPost<void>(`/users/${id}/restore`, {});
};

// Unlock user
export const unlockUser = async (id: string): Promise<void> => {
  return apiPost<void>(`/authorization/users/${id}/unlock`, {});
};

// Get role list
export const getRoles = async (): Promise<API.PaginationResponse<API.Role>> => {
  return apiGet<API.PaginationResponse<API.Role>>('/authorization/roles');
};

export const getUserApplications = async (id: string, current?: number, pageSize?: number): Promise<API.PaginationResponse<API.Application>> => {
  return apiGet<API.PaginationResponse<API.Application>>(`/users/${id}/applications`, {
    params: { current, page_size: pageSize },
  });
};

export const getUserAssignableApplications = async (id: string, keywords?: string): Promise<API.PaginationResponse<API.Application>> => {
  return apiGet<API.PaginationResponse<API.Application>>(`/users/${id}/assignable-applications`, {
    params: { keywords },
  });
};

export const getMySelfApplications = async (keywords?: string, current?: number, pageSize?: number): Promise<API.PaginationResponse<API.Application>> => {
  return apiGet<API.PaginationResponse<API.Application>>(`/users/my-self/applications`, {
    params: { current, page_size: pageSize, keywords, status: 'active' },
  });
};