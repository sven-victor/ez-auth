export interface OIDCClient {
  id: string;
  name: string;
  description: string;
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  grantTypes: string[];
  scopes: string[];
  tokenEndpointAuthMethod: string;
  responseTypes: string[];
  status: 'active' | 'inactive';
  createdAt: string;
  updatedAt: string;
}

export interface OIDCClientCreateRequest {
  name: string;
  description: string;
  redirectUris: string[];
  grantTypes: string[];
  scopes: string[];
  tokenEndpointAuthMethod: string;
  responseTypes: string[];
  status: 'active' | 'inactive';
}

export interface OIDCClientUpdateRequest {
  name: string;
  description: string;
  redirectUris: string[];
  grantTypes: string[];
  scopes: string[];
  tokenEndpointAuthMethod: string;
  responseTypes: string[];
  status: 'active' | 'inactive';
}

export interface OIDCClientListResponse {
  data: OIDCClient[];
  total: number;
  current: number;
  page_size: number;
} 