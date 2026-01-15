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
      enabled: 'Enable LDAP Authentication',
      serverUrl: 'LDAP Server URL',
      bindDn: 'Bind DN',
      bindPassword: 'Bind Password',
      baseDn: 'Base DN',
      userFilter: 'User Filter',
      userAttr: 'User Attribute',
      emailAttr: 'Email Attribute',
      displayNameAttr: 'Display Name Attribute',
      autoCreateUser: 'Auto Create User',
      defaultRole: 'Default Role',
      importUsers: 'Import LDAP Users',
      testConnection: 'Test Connection',
      import: 'Import Users',
      save: 'Save Settings',
      loadError: 'Failed to load LDAP settings: {{error}}',
      saveSuccess: 'LDAP settings updated successfully',
      saveError: 'Failed to update LDAP settings',
      testError: 'Failed to test LDAP connection: {{error}}',
      importSuccess: 'LDAP users imported successfully',
      importError: 'Failed to import LDAP users: {{error}}',
      serverUrlRequired: 'Please enter the LDAP server URL',
      bindDnRequired: 'Please enter the bind DN',
      bindPasswordRequired: 'Please enter the bind password',
      baseDnRequired: 'Please enter the base DN',
      userFilterRequired: 'Please enter the user filter',
      userAttrRequired: 'Please enter the user attribute',
      emailAttrRequired: 'Please enter the email attribute',
      displayNameAttrRequired: 'Please enter the display name attribute',
      defaultRoleRequired: 'Please enter the default role',
      test: {
        title: 'Test LDAP Connection',
        username: 'Username',
        password: 'Password',
        test: 'Test',
        cancel: 'Cancel',
        usernameRequired: 'Please enter the username',
        passwordRequired: 'Please enter the password',
      },
      tlsDivider: 'TLS Configuration',
      startTls: 'Enable TLS',
      insecure: 'Do not check certificate',
      caCert: 'CA Certificate',
      clientCert: 'Client Certificate',
      clientCertPlaceholder: 'Please enter the client certificate',
      clientKey: 'Client Key',
      applicationDivider: 'Application LDAP Configuration',
      applicationLdapEnabled: 'Enable Application LDAP',
      applicationLdapEnabledTooltip: 'Enable LDAP-based application management. When enabled, applications can be stored in LDAP directory.',
      applicationBaseDn: 'Application Base DN',
      applicationBaseDnRequired: 'Please enter application base DN',
      applicationFilter: 'Application Filter',
      applicationObjectClass: 'Application Object Class',
      clientKeyPlaceholder: 'Do not modify',
      importTitle: 'Import LDAP Users',
      checkAll: 'Check all',
      caCertPlaceholder: 'Please enter the CA certificate',
      importUser: 'Import User',
      importApplication: 'Import Application',
      username: 'Username',
      email: 'Email',
      fullName: 'Full Name',
      importStatus: 'Import Status',
      importTypeBound: 'Bound',
      importTypeNew: 'New',
      applicationFilterRequired: 'Please enter the application filter',
    },
  },
}; 