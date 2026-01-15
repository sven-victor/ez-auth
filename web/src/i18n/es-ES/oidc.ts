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
    title: "Autorización de la aplicación",
    description: "La aplicación solicita acceso a la siguiente información sobre usted:",
    new: "Nuevo",
    approve: "Aprobar",
    cancel: "Cancelar",
    missingClientId: "Falta el ID de cliente",
    missingRedirectUri: "Falta la URI de redirección",
    missingResponseType: "Falta el tipo de respuesta",
    missingState: "Falta el parámetro de estado",
    invalidResponseType: "Tipo de respuesta no válido",
    missingParams: "Faltan parámetros obligatorios",
    failed: "Error de autorización",
    error: "Error de autorización: {{error}}"
  },
  test: {
    failedVerifyIdToken: "Error al verificar el token de ID",
    clientSecret: "Secreto de cliente",
    clientID: "ID de cliente",
    redirectURI: "URI de redirección",
    responseType: "Tipo de respuesta",
    scope: "Ámbito",
    state: "Estado",
    nonce: "Nonce",
    codeVerifier: "Verificador de código",
    codeChallenge: "Desafío de código",
    codeChallengeMethod: "Método de desafío de código",
    code: "Código de autorización",
    token: "Token",
    status: "Estado",
    auth: "Autenticación",
    userInfo: "Información del usuario",
    idToken: "Token de ID",
    accessToken: "Token de acceso",
    title: "Página de prueba de OIDC",
    oidcConfig: {
      invalidURL: "URL no válida",
      authorizationEndpointRequired: "Se requiere el punto final de autorización",
      tokenEndpointRequired: "Se requiere el punto final del token",
      userinfoEndpointRequired: "Se requiere el punto final de información del usuario",
      title: "Información de configuración de OIDC",
      authorizationEndpoint: "Punto final de autorización",
      tokenEndpoint: "Punto final del token",
      userinfoEndpoint: "Punto final de información del usuario",
      jwksEndpoint: "Punto final de JWKS",
      scope: "Ámbito",
      issuer: "Emisor",
      scopeRequired: "Se requiere el ámbito",
    },
    oidcStatus: {
      code: {
        title: "Obtener código de autorización"
      },
      token: {
        idToken: "Token de ID",
        accessToken: "Token de acceso",
        title: "Obtener token"
      },
      userInfo: {
        title: "Obtener información del usuario"
      },
      refreshToken: {
        title: "Actualizar token"
      },
      idToken: {
        title: "Obtener/verificar token de ID"
      },
    },
  },
  callback: {
    processing: "Procesando autorización...",
    success: "Autorización correcta",
    failed: "Error de autorización",
    noCode: "No se recibió ningún código de autorización",
    closeNow: "Cerrar inmediatamente",
    closeIn: "La página se cerrará en {{timerInterval}} segundos",
    close: "Cerrar inmediatamente"
  }
}; 