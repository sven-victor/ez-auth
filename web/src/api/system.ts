/**
 * Copyright 2026 Sven Victor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
