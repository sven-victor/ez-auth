import { apiGet, apiPost, apiPut, apiDelete } from './client';

// Get application list
export const getApplications = async (keywords?: string, status?: string, page?: number, pageSize?: number): Promise<API.ApplicationListResponse> => {
  return apiGet<API.ApplicationListResponse>(`/applications`, {
    params: {
      page,
      page_size: pageSize,
      keywords,
      status,
    },
  });
};

// Get application details
export const getApplication = async (id: string): Promise<API.Application> => {
  return apiGet<API.Application>(`/applications/${id}`);
};

// Create application
export const createApplication = async (data: API.ApplicationCreateRequest): Promise<API.Application> => {
  return apiPost<API.Application>('/applications', data);
};

// Update application
export const updateApplication = async (id: string, data: API.ApplicationUpdateRequest): Promise<API.Application> => {
  return apiPut<API.Application>(`/applications/${id}`, data);
};

// Delete application
export const deleteApplication = async (id: string): Promise<void> => {
  return apiDelete(`/applications/${id}`);
};


// Create application key
export const createApplicationKey = (applicationId: string, data: { name: string; expiresAt?: string }): Promise<API.ApplicationKey> => {
  return apiPost<API.ApplicationKey>(`/applications/${applicationId}/keys`, {
    name: data.name,
    expires_at: data.expiresAt,
  });
};

// Delete application key
export const deleteApplicationKey = (applicationId: string, keyId: string): Promise<void> => {
  return apiDelete(`/applications/${applicationId}/keys/${keyId}`);
};

// Get application key list
export const getApplicationKeys = (applicationId: string): Promise<API.ApplicationKey[]> => {
  return apiGet<API.ApplicationKey[]>(`/applications/${applicationId}/keys`);
};

// Get application role list
export const getApplicationRoles = (applicationId: string): Promise<API.ApplicationRole[]> => {
  return apiGet<API.ApplicationRole[]>(`/applications/${applicationId}/roles`);
};

// Create application role
export const createApplicationRole = (applicationId: string, data: { name: string; description: string }): Promise<API.ApplicationRole> => {
  return apiPost<API.ApplicationRole>(`/applications/${applicationId}/roles`, data);
};

// Update application role
export const updateApplicationRole = (applicationId: string, roleId: string, data: { name: string; description: string }): Promise<API.ApplicationRole> => {
  return apiPut<API.ApplicationRole>(`/applications/${applicationId}/roles/${roleId}`, data);
};

// Delete application role
export const deleteApplicationRole = (applicationId: string, roleId: string): Promise<void> => {
  return apiDelete(`/applications/${applicationId}/roles/${roleId}`);
};

// Assign user to application (with role)
export const assignUserToApplication = (applicationId: string, userId: string, roleId?: string): Promise<void> => {
  return apiPut(`/applications/${applicationId}/users`, {
    user_id: userId,
    role_id: roleId,
  });
};

// Remove user from application
export const removeUserFromApplication = (applicationId: string, userId: string): Promise<void> => {
  return apiDelete(`/applications/${applicationId}/users/${userId}`);
};

// Get application issuer keys
export const getApplicationIssuerKeys = async (applicationId: string): Promise<API.ApplicationIssuerKey[]> => {
  return apiGet<API.ApplicationIssuerKey[]>(`/applications/${applicationId}/issuer_keys`);
};

// Create application issuer key
export const createApplicationIssuerKey = async (applicationId: string, data: API.ApplicationIssuerKeyCreateRequest): Promise<API.ApplicationIssuerKey> => {
  return apiPost<API.ApplicationIssuerKey>(`/applications/${applicationId}/issuer_keys`, data);
};


// Delete application issuer key
export const deleteApplicationIssuerKey = (applicationId: string, keyId: string): Promise<void> => {
  return apiDelete(`/applications/${applicationId}/issuer_keys/${keyId}`);
};


