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

export default {
  authorize: {
    title: "Application Authorization",
    description: "The application requests access to the following information about you:",
    new: "New",
    approve: "Approve",
    cancel: "Cancel",
    missingClientId: "Missing client ID",
    missingRedirectUri: "Missing redirect URI",
    missingResponseType: "Missing response type",
    missingState: "Missing state parameter",
    invalidResponseType: "Invalid response type",
    missingParams: "Missing required parameters",
    failed: "Authorization failed",
    error: "Authorization error: {{error}}"
  },
  test: {
    failedVerifyIdToken: "Failed to verify ID Token",
    clientSecret: "Client Secret",
    clientID: "Client ID",
    redirectURI: "Redirect URI",
    responseType: "Response Type",
    scope: "Scope",
    state: "State",
    nonce: "Nonce",
    codeVerifier: "Code Verifier",
    codeChallenge: "Code Challenge",
    codeChallengeMethod: "Code Challenge Method",
    code: "Authorization Code",
    token: "Token",
    status: "Status",
    auth: "Auth",
    userInfo: "User Info",
    idToken: "ID Token",
    accessToken: "Access Token",
    title: "OIDC Test Page",
    oidcConfig: {
      invalidURL: "Invalid URL",
      authorizationEndpointRequired: "Authorization endpoint is required",
      tokenEndpointRequired: "Token endpoint is required",
      userinfoEndpointRequired: "Userinfo endpoint is required",
      title: "OIDC Configuration Information",
      authorizationEndpoint: "Authorization Endpoint",
      tokenEndpoint: "Token Endpoint",
      userinfoEndpoint: "Userinfo Endpoint",
      jwksEndpoint: "JWKS Endpoint",
      scope: "Scope",
      issuer: "Issuer",
      scopeRequired: "Scope is required",
    },
    oidcStatus: {
      code: {
        title: "Get Authorization Code"
      },
      token: {
        idToken: "ID Token",
        accessToken: "Access Token",
        title: "Get Token"
      },
      userInfo: {
        title: "Get User Info"
      },
      refreshToken: {
        title: "Refresh Token"
      },
      idToken: {
        title: "Get/Verify ID Token"
      },
    },
  },
  callback: {
    processing: "Processing authorization...",
    success: "Authorization successful",
    failed: "Authorization failed",
    noCode: "No authorization code received",
    closeNow: "Close immediately",
    closeIn: "{{timerInterval}} seconds to close the page",
    close: "Close immediately"
  }
};
