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