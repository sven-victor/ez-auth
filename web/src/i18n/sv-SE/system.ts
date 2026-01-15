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
      enabled: 'Aktivera LDAP-autentisering',
      serverUrl: 'LDAP-server-URL',
      bindDn: 'Bind DN',
      bindPassword: 'Bind-lösenord',
      baseDn: 'Base DN',
      userFilter: 'Användarfilter',
      userAttr: 'Användarattribut',
      emailAttr: 'E-postattribut',
      displayNameAttr: 'Visningsnamnattribut',
      autoCreateUser: 'Skapa användare automatiskt',
      defaultRole: 'Standardroll',
      importUsers: 'Importera LDAP-användare',
      testConnection: 'Testa anslutning',
      import: 'Importera användare',
      save: 'Spara inställningar',
      loadError: 'Kunde inte ladda LDAP-inställningar: {{error}}',
      saveSuccess: 'LDAP-inställningar uppdaterades',
      saveError: 'Kunde inte uppdatera LDAP-inställningar',
      testError: 'Kunde inte testa LDAP-anslutning: {{error}}',
      importSuccess: 'LDAP-användare importerades',
      importError: 'Kunde inte importera LDAP-användare: {{error}}',
      serverUrlRequired: 'Ange LDAP-server-URL',
      bindDnRequired: 'Ange bind-DN',
      bindPasswordRequired: 'Ange bind-lösenord',
      baseDnRequired: 'Ange base-DN',
      userFilterRequired: 'Ange användarfilter',
      userAttrRequired: 'Ange användarattribut',
      emailAttrRequired: 'Ange e-postattribut',
      displayNameAttrRequired: 'Ange visningsnamnattribut',
      defaultRoleRequired: 'Ange standardroll',
      test: {
        title: 'Testa LDAP-anslutning',
        username: 'Användarnamn',
        password: 'Lösenord',
        test: 'Testa',
        cancel: 'Avbryt',
        usernameRequired: 'Ange användarnamn',
        passwordRequired: 'Ange lösenord',
      },
      tlsDivider: 'TLS-konfiguration',
      startTls: 'Aktivera TLS',
      insecure: 'Kontrollera inte certifikat',
      caCert: 'CA-certifikat',
      clientCert: 'Klientcertifikat',
      clientCertPlaceholder: 'Ange klientcertifikat',
      clientKey: 'Klientnyckel',
      clientKeyPlaceholder: 'Ändra inte',
      importTitle: 'Importera LDAP-användare',
      checkAll: 'Markera alla',
      applicationBaseDn: 'Applikationens Base DN',
      applicationFilter: 'Applikationsfilter',
      caCertPlaceholder: 'Ange CA-certifikat',
      importUser: 'Importera användare',
      importApplication: 'Importera applikation',
      username: 'Användarnamn',
      email: 'E-post',
      fullName: 'Fullständigt namn',
      importStatus: 'Importstatus',
      importTypeBound: 'Bunden',
      importTypeNew: 'Ny',
      applicationBaseDnRequired: 'Ange applikationens base-DN',
      applicationFilterRequired: 'Ange applikationsfilter',
    },
  },
}; 