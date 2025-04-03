import { apiGet, apiPost } from './client';

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