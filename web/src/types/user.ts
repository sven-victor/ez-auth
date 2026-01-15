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

export type UserCreateRequest = {
  username: string;
  email: string;
  full_name: string;
  mfa_enforced: boolean;
  source: string;
  role_ids: string[];
  phone?: string;
  avatar?: string;
  password?: string;
} | {
  ldap_attrs: API.LDAPAttrs[];
}

export type UserUpdateRequest = {
  email: string;
  full_name: string;
  status: 'active' | 'inactive';
  mfa_enforced: boolean;
  source?: string;
  role_ids?: string[];
  phone?: string;
  avatar?: string;
  ldap_dn?: string;
} | {
  ldap_attrs: API.LDAPAttrs[];
}

export interface UserListResponse {
  code: string;
  data: API.User[];
  total: number;
  current: number;
  page_size: number;
}

export interface UserQueryParams {
  username?: string;
  email?: string;
  status?: 'active' | 'inactive';
  current?: number;
  page_size?: number;
}
