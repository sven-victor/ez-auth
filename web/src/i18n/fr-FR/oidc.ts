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
    title: "Autorisation de l'application",
    description: "L'application demande l'accès aux informations suivantes vous concernant :",
    new: "Nouveau",
    approve: "Approuver",
    cancel: "Annuler",
    missingClientId: "ID client manquant",
    missingRedirectUri: "URI de redirection manquante",
    missingResponseType: "Type de réponse manquant",
    missingState: "Paramètre d'état manquant",
    invalidResponseType: "Type de réponse non valide",
    missingParams: "Paramètres requis manquants",
    failed: "Échec de l'autorisation",
    error: "Erreur d'autorisation : {{error}}"
  },
  test: {
    failedVerifyIdToken: "Échec de la vérification du jeton d'ID",
    clientSecret: "Secret client",
    clientID: "ID client",
    redirectURI: "URI de redirection",
    responseType: "Type de réponse",
    scope: "Portée",
    state: "État",
    nonce: "Nonce",
    codeVerifier: "Vérificateur de code",
    codeChallenge: "Défi de code",
    codeChallengeMethod: "Méthode de défi de code",
    code: "Code d'autorisation",
    token: "Jeton",
    status: "Statut",
    auth: "Authentification",
    userInfo: "Informations utilisateur",
    idToken: "Jeton d'ID",
    accessToken: "Jeton d'accès",
    title: "Page de test OIDC",
    oidcConfig: {
      invalidURL: "URL non valide",
      authorizationEndpointRequired: "Point de terminaison d'autorisation requis",
      tokenEndpointRequired: "Point de terminaison de jeton requis",
      userinfoEndpointRequired: "Point de terminaison d'informations utilisateur requis",
      title: "Informations de configuration OIDC",
      authorizationEndpoint: "Point de terminaison d'autorisation",
      tokenEndpoint: "Point de terminaison de jeton",
      userinfoEndpoint: "Point de terminaison d'informations utilisateur",
      jwksEndpoint: "Point de terminaison JWKS",
      scope: "Portée",
      issuer: "Émetteur",
      scopeRequired: "Portée requise",
    },
    oidcStatus: {
      code: {
        title: "Obtenir le code d'autorisation"
      },
      token: {
        idToken: "Jeton d'ID",
        accessToken: "Jeton d'accès",
        title: "Obtenir le jeton"
      },
      userInfo: {
        title: "Obtenir les informations utilisateur"
      },
      refreshToken: {
        title: "Actualiser le jeton"
      },
      idToken: {
        title: "Obtenir/vérifier le jeton d'ID"
      },
    },
  },
  callback: {
    processing: "Traitement de l'autorisation...",
    success: "Autorisation réussie",
    failed: "Échec de l'autorisation",
    noCode: "Aucun code d'autorisation reçu",
    closeNow: "Fermer immédiatement",
    closeIn: "La page se fermera dans {{timerInterval}} secondes",
    close: "Fermer immédiatement"
  }
}; 