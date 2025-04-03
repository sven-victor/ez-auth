export default {
  authorize: {
    title: "Anwendungsautorisierung",
    description: "Die Anwendung fordert Zugriff auf die folgenden Informationen über Sie:",
    new: "Neu",
    approve: "Genehmigen",
    cancel: "Abbrechen",
    missingClientId: "Client-ID fehlt",
    missingRedirectUri: "Weiterleitungs-URI fehlt",
    missingResponseType: "Antworttyp fehlt",
    missingState: "Statusparameter fehlt",
    invalidResponseType: "Ungültiger Antworttyp",
    missingParams: "Erforderliche Parameter fehlen",
    failed: "Autorisierung fehlgeschlagen",
    error: "Autorisierungsfehler: {{error}}"
  },
  test: {
    failedVerifyIdToken: "ID-Token konnte nicht überprüft werden",
    clientSecret: "Client-Geheimnis",
    clientID: "Client-ID",
    redirectURI: "Weiterleitungs-URI",
    responseType: "Antworttyp",
    scope: "Geltungsbereich",
    state: "Status",
    nonce: "Nonce",
    codeVerifier: "Code-Prüfer",
    codeChallenge: "Code-Herausforderung",
    codeChallengeMethod: "Code-Herausforderungsmethode",
    code: "Autorisierungscode",
    token: "Token",
    status: "Status",
    auth: "Auth",
    userInfo: "Benutzerinfo",
    idToken: "ID-Token",
    accessToken: "Zugriffstoken",
    title: "OIDC-Testseite",
    oidcConfig: {
      invalidURL: "Ungültige URL",
      authorizationEndpointRequired: "Autorisierungsendpunkt erforderlich",
      tokenEndpointRequired: "Token-Endpunkt erforderlich",
      userinfoEndpointRequired: "Benutzerinfo-Endpunkt erforderlich",
      title: "OIDC-Konfigurationsinformationen",
      authorizationEndpoint: "Autorisierungsendpunkt",
      tokenEndpoint: "Token-Endpunkt",
      userinfoEndpoint: "Benutzerinfo-Endpunkt",
      jwksEndpoint: "JWKS-Endpunkt",
      scope: "Geltungsbereich",
      issuer: "Aussteller",
      scopeRequired: "Geltungsbereich erforderlich",
    },
    oidcStatus: {
      code: {
        title: "Autorisierungscode abrufen"
      },
      token: {
        idToken: "ID-Token",
        accessToken: "Zugriffstoken",
        title: "Token abrufen"
      },
      userInfo: {
        title: "Benutzerinfo abrufen"
      },
      refreshToken: {
        title: "Token aktualisieren"
      },
      idToken: {
        title: "ID-Token abrufen/überprüfen"
      },
    },
  },
  callback: {
    processing: "Autorisierung wird verarbeitet...",
    success: "Autorisierung erfolgreich",
    failed: "Autorisierung fehlgeschlagen",
    noCode: "Kein Autorisierungscode empfangen",
    closeNow: "Sofort schließen",
    closeIn: "Seite wird in {{timerInterval}} Sekunden geschlossen",
    close: "Sofort schließen"
  }
}; 