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
