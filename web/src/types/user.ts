export type UserCreateRequest = {
  username: string;
  email: string;
  full_name: string;
  mfa_enforced: boolean;
  source: string;
  role_ids: string[];
  phone?: string;
  avatar?: string;
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
