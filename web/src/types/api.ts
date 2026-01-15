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

namespace API {
  export interface Entity {
    id: string;
    created_at: string;
    updated_at: string;
  }

  export interface PaginationRequest {
    current: number;
    page_size: number;
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

  export interface PolicyDocument {
    Statement: {
      Effect: string;
      Action: string[];
      Resource: string[];
      Condition?: Record<string, any>;
    }[];
  }

  export interface Permission {
    id: string;
    code: string;
    name: string;
    description: string;
    created_at: string;
    updated_at: string;
  }
  export interface Role {
    id: string;
    name: string;
    description: string;
    created_at: string;
    updated_at: string;
    permissions?: Permission[];
    policy_document?: PolicyDocument;
  }

  export interface LDAPAttrs {
    name: string;
    value: string;
    user_attr?: boolean;
    base64?: boolean;
  }
  export interface User {
    id: string;
    username: string;
    email: string;
    full_name: string;
    phone?: string;
    avatar?: string;
    status: string;
    last_login?: string;
    created_at: string;
    updated_at: string;
    roles?: Role[];
    permissions?: string[];
    mfa_enabled: boolean;
    mfa_enforced: boolean;
    oauth_provider?: string;
    oauth_id?: string;
    source?: string;
    ldap_attrs?: LDAPAttrs[];
    ldap_dn?: string;
  }
  export interface Navigation {
    name: string;
    path: string;
  }

  export interface LDAPSettings {
    enabled: boolean;
    server_url: string;
    bind_dn: string;
    bind_password: string;
    base_dn: string;
    user_filter: string;
    application_ldap_enabled: boolean;
    application_filter: string;
    application_base_dn: string;
    application_object_class: string;
    user_attr: string;
    email_attr: string;
    display_name_attr: string;
    auto_create_user: boolean;
    default_role: string;
    ca_cert: string;
    client_cert: string;
    client_key: string;
    insecure: boolean;
  }
  export interface LDAPTestRequest extends LDAPSettings {
    username: string;
    password: string;
  }

  export interface LDAPTestResponse {
    success: boolean;
    message?: {
      success: boolean;
      message: string;
    }[];
    user?: User;
  }

  export interface ImportLDAPUsersRequest {
    user_dn?: string[];
  }

  export interface ImportLDAPUsersResponse {
    username: string;
    email: string;
    full_name: string;
    id: string;
    create_time: string;
    modify_time: string;
    ldap_dn: string;
    imported: boolean;
  }
  export interface ImportLDAPApplicationsRequest {
    application_dn?: string[];
  }

  export interface ImportLDAPApplicationsResponse extends Application {
    ldap_dn: string;
    imported: boolean;
  }
  export interface ApplicationRole {
    id: string;
    name: string;
    description: string;
    application_id: string;
    created_at: string;
    updated_at: string;
  }

  export interface Application {
    id: string;
    name: string;
    display_name: string;
    display_name_i18n: Record<string, string>;
    description: string;
    description_i18n: Record<string, string>;
    status: 'active' | 'inactive';
    source: 'ldap' | 'local';
    grant_types: string[];
    uri: string;
    redirect_uris: string[];
    scopes: string[];
    client_id: string;
    client_secret: string;
    created_at: string;
    updated_at: string;
    keys?: ApplicationKey[];
    users?: ApplicationUser[];
    roles?: ApplicationRole[];
    icon?: string;
    ldap_attrs?: LDAPAttrs[];
    force_independent_password?: boolean;
    has_password?: boolean;
    organization_name?: string;
    organization_id?: string;
  }

  export interface ApplicationUser {
    id: string;
    created_at: string;
    updated_at: string;
    username: string;
    email: string;
    full_name: string;
    status: string;
    mfa_enabled: boolean;
    ldap_dn: string;
    mfa_enforced: boolean;
    source: string;
    ldap_attrs: LDAPAttrs[];
    role: string;
    role_id: string;
  }

  export type ApplicationCreateRequest = {
    name: string;
    display_name?: string;
    display_name_i18n?: Record<string, string>;
    description?: string;
    description_i18n?: Record<string, string>;
    uri?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    scopes?: string[];
    status: 'active' | 'inactive';
    source?: 'ldap' | 'local';
    icon?: string;
    i18n?: {
      display_name?: Record<string, any>;
      description?: Record<string, any>;
    };
    force_independent_password?: boolean;
  } | {
    ldap_attrs?: LDAPAttrs[];
    source?: 'ldap' | 'local';
  }

  export type ApplicationUpdateRequest = {
    name: string;
    display_name?: string;
    description?: string;
    uri?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    scopes?: string[];
    status: 'active' | 'inactive';
    icon?: string;
    i18n?: {
      display_name?: Record<string, any>;
      description?: Record<string, any>;
    };
  } | {
    ldap_attrs?: LDAPAttrs[];
  }

  export interface ApplicationListResponse {
    data: Application[];
    total: number;
    current: number;
    page_size: number;
  }

  export interface ApplicationKey {
    id: string;
    name: string;
    client_id: string;
    client_secret: string;
    expires_at?: string;
    created_at: string;
  }
  export interface File {
    id: string;
    name: string;
    size: number;
    created_at: string;
    updated_at: string;
  }
  export interface OIDCConfig {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    jwks_uri?: string;
    response_types_supported?: string[];
    subject_types_supported?: string[];
    id_token_signing_alg_values_supported?: string[];
    scopes_supported?: string[];
    token_endpoint_auth_methods_supported?: string[];
    claims_supported?: string[];
    code_challenge_methods_supported?: string[];
    introspection_endpoint?: string;
    revocation_endpoint?: string;
    grant_types_supported?: string[];
  }
  export interface ExchangeTokenParams {
    token_endpoint: string;
    refresh_token?: string;
    client_id: string;
    client_secret: string;
    code?: string;
    state?: string;
    code_verifier?: string;
  }
  export interface ApplicationAuthorization {
    id: string;
    created_at: string;
    updated_at: string;
    user_id: string;
    application_id: string;
    application: Application;
    scopes?: string[];
  }
  export interface AuthorizeApplicationParams {
    client_id: string;
    redirect_uri: string;
    scope: string;
    response_type: string;
    state: string;
    nonce?: string;
    code_challenge?: string;
    code_challenge_method?: string;
  }
  export interface AuthorizeApplicationResponse {
    redirect_uri: string;
  }

  export interface ApplicationIssuerKey {
    id: string;
    name: string;
    algorithm: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512';
    created_at: string;
  }
  export interface ApplicationIssuerKeyCreateRequest {
    name: string;
    algorithm: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512';
    private_key?: string;
  }

  export interface MenuConfig {
    name: string;
    path: string;
    icon: string;
    hidden: boolean;
  }
}

