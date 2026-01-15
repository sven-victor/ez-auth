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