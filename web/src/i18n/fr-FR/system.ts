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
  settings: {
    ldap: {
      enabled: 'Activer l\'authentification LDAP',
      serverUrl: 'URL du serveur LDAP',
      bindDn: 'DN de liaison',
      bindPassword: 'Mot de passe de liaison',
      baseDn: 'DN de base',
      userFilter: 'Filtre utilisateur',
      userAttr: 'Attribut utilisateur',
      emailAttr: 'Attribut d\'e-mail',
      displayNameAttr: 'Attribut de nom d\'affichage',
      autoCreateUser: 'Créer automatiquement un utilisateur',
      defaultRole: 'Rôle par défaut',
      importUsers: 'Importer des utilisateurs LDAP',
      testConnection: 'Tester la connexion',
      import: 'Importer des utilisateurs',
      save: 'Enregistrer les paramètres',
      loadError: 'Échec du chargement des paramètres LDAP : {{error}}',
      saveSuccess: 'Paramètres LDAP mis à jour avec succès',
      saveError: 'Échec de la mise à jour des paramètres LDAP',
      testError: 'Échec du test de la connexion LDAP : {{error}}',
      importSuccess: 'Utilisateurs LDAP importés avec succès',
      importError: 'Échec de l\'importation des utilisateurs LDAP : {{error}}',
      serverUrlRequired: 'Veuillez saisir l\'URL du serveur LDAP',
      bindDnRequired: 'Veuillez saisir le DN de liaison',
      bindPasswordRequired: 'Veuillez saisir le mot de passe de liaison',
      baseDnRequired: 'Veuillez saisir le DN de base',
      userFilterRequired: 'Veuillez saisir le filtre utilisateur',
      userAttrRequired: 'Veuillez saisir l\'attribut utilisateur',
      emailAttrRequired: 'Veuillez saisir l\'attribut d\'e-mail',
      displayNameAttrRequired: 'Veuillez saisir l\'attribut de nom d\'affichage',
      defaultRoleRequired: 'Veuillez saisir le rôle par défaut',
      test: {
        title: 'Tester la connexion LDAP',
        username: 'Nom d\'utilisateur',
        password: 'Mot de passe',
        test: 'Tester',
        cancel: 'Annuler',
        usernameRequired: 'Veuillez saisir le nom d\'utilisateur',
        passwordRequired: 'Veuillez saisir le mot de passe',
      },
      tlsDivider: 'Configuration TLS',
      startTls: 'Activer TLS',
      insecure: 'Ne pas vérifier le certificat',
      caCert: 'Certificat CA',
      clientCert: 'Certificat client',
      clientCertPlaceholder: 'Veuillez saisir le certificat client',
      clientKey: 'Clé client',
      clientKeyPlaceholder: 'Ne pas modifier',
      importTitle: 'Importer des utilisateurs LDAP',
      checkAll: 'Tout cocher',
      applicationBaseDn: 'DN de base de l\'application',
      applicationFilter: 'Filtre d\'application',
      caCertPlaceholder: 'Veuillez saisir le certificat CA',
      importUser: 'Importer un utilisateur',
      importApplication: 'Importer une application',
      username: 'Nom d\'utilisateur',
      email: 'E-mail',
      fullName: 'Nom complet',
      importStatus: 'Statut d\'importation',
      importTypeBound: 'Lié',
      importTypeNew: 'Nouveau',
      applicationBaseDnRequired: 'Veuillez saisir le DN de base de l\'application',
      applicationFilterRequired: 'Veuillez saisir le filtre d\'application',
    },
  },
}; 