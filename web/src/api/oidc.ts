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

export function getOIDCConfig(data: {
  wellknow_endpoint?: string;
  client_id?: string;
}) {
  return apiPost<API.OIDCConfig | {}>(`/oidc/test`, data);
}
export function getJWKS(data: {
  jwks_endpoint: string;
  client_id?: string;
}) {
  return apiPost<Record<string, any>>(`/oidc/test`, data);
}

export function exchangeToken(data: {
  code?: string;
  refresh_token?: string;
  token_endpoint: string;
  client_id: string;
  client_secret: string;
}) {
  return apiPost<{
    access_token: string;
    refresh_token: string;
    id_token?: string;
    expires_in: number;
    scope: string;
    token_type: string;
  }>(`/oidc/test`, data);
}

export function getUserInfo(data: {
  userinfo_endpoint: string;
  access_token: string;
}) {
  return apiPost<Record<string, any>>(`/oidc/test`, data);
}


// Get application information by ClientID
export const getApplicationByClientId = (clientId: string): Promise<Partial<API.ApplicationAuthorization>> => {
  return apiGet<Partial<API.ApplicationAuthorization>>(`/oauth2/applications/client_id/${clientId}`);
};

// Authorize application
export const authorizeApplication = (params: API.AuthorizeApplicationParams) => {
  return apiGet<API.AuthorizeApplicationResponse>(`/oauth2/authorize`, {
    params,
    headers: {
      'Accept': 'application/json',
    }
  });
};