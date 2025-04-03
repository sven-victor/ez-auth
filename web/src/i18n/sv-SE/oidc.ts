export default {
  authorize: {
    title: "Applikationsauktorisering",
    description: "Applikationen begär åtkomst till följande information om dig:",
    new: "Ny",
    approve: "Godkänn",
    cancel: "Avbryt",
    missingClientId: "Klient-ID saknas",
    missingRedirectUri: "Omdirigerings-URI saknas",
    missingResponseType: "Svarstyp saknas",
    missingState: "Tillståndsparameter saknas",
    invalidResponseType: "Ogiltig svarstyp",
    missingParams: "Obligatoriska parametrar saknas",
    failed: "Auktorisering misslyckades",
    error: "Auktoriseringsfel: {{error}}"
  },
  test: {
    failedVerifyIdToken: "Kunde inte verifiera ID-token",
    clientSecret: "Klienthemlighet",
    clientID: "Klient-ID",
    redirectURI: "Omdirigerings-URI",
    responseType: "Svarstyp",
    scope: "Omfattning",
    state: "Tillstånd",
    nonce: "Nonce",
    codeVerifier: "Kodverifierare",
    codeChallenge: "Kodutmaning",
    codeChallengeMethod: "Metod för kodutmaning",
    code: "Auktoriseringskod",
    token: "Token",
    status: "Status",
    auth: "Autentisering",
    userInfo: "Användarinfo",
    idToken: "ID-token",
    accessToken: "Åtkomsttoken",
    title: "OIDC-testsida",
    oidcConfig: {
      invalidURL: "Ogiltig URL",
      authorizationEndpointRequired: "Auktoriseringsslutpunkt krävs",
      tokenEndpointRequired: "Tokenslutpunkt krävs",
      userinfoEndpointRequired: "Användarinfoslutpunkt krävs",
      title: "OIDC-konfigurationsinformation",
      authorizationEndpoint: "Auktoriseringsslutpunkt",
      tokenEndpoint: "Tokenslutpunkt",
      userinfoEndpoint: "Användarinfoslutpunkt",
      jwksEndpoint: "JWKS-slutpunkt",
      scope: "Omfattning",
      issuer: "Utfärdare",
      scopeRequired: "Omfattning krävs",
    },
    oidcStatus: {
      code: {
        title: "Hämta auktoriseringskod"
      },
      token: {
        idToken: "ID-token",
        accessToken: "Åtkomsttoken",
        title: "Hämta token"
      },
      userInfo: {
        title: "Hämta användarinfo"
      },
      refreshToken: {
        title: "Uppdatera token"
      },
      idToken: {
        title: "Hämta/verifiera ID-token"
      },
    },
  },
  callback: {
    processing: "Bearbetar auktorisering...",
    success: "Auktorisering lyckades",
    failed: "Auktorisering misslyckades",
    noCode: "Ingen auktoriseringskod mottagen",
    closeNow: "Stäng omedelbart",
    closeIn: "{{timerInterval}} sekunder för att stänga sidan",
    close: "Stäng omedelbart"
  }
}; 