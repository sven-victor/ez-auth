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