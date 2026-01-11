import { apiGet, apiPost } from 'ez-console';




const baseUrl = '/ldap';


// LDAP settings related APIs
export const getLDAPSettings = () => {
  return apiGet<API.LDAPSettings>(`${baseUrl}/settings`);
};

export const updateLDAPSettings = (data: API.LDAPSettings) => {
  return apiPost<void>(`${baseUrl}/settings`, data);
};

export const testLDAPConnection = (data: API.LDAPTestRequest) => {
  return apiPost<API.LDAPTestResponse>(`${baseUrl}/test`, data);
};

export const importLDAPUsers = (data: API.ImportLDAPUsersRequest) => {
  return apiPost<API.ImportLDAPUsersResponse[]>(`/users/import`, data);
};

export const importLDAPApplications = (data: API.ImportLDAPApplicationsRequest) => {
  return apiPost<API.ImportLDAPApplicationsResponse[]>(`/applications/import`, data);
};
