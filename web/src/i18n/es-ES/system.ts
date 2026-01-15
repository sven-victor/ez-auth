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
      enabled: 'Habilitar autenticación LDAP',
      serverUrl: 'URL del servidor LDAP',
      bindDn: 'DN de enlace',
      bindPassword: 'Contraseña de enlace',
      baseDn: 'DN base',
      userFilter: 'Filtro de usuario',
      userAttr: 'Atributo de usuario',
      emailAttr: 'Atributo de correo electrónico',
      displayNameAttr: 'Atributo de nombre para mostrar',
      autoCreateUser: 'Crear usuario automáticamente',
      defaultRole: 'Rol predeterminado',
      importUsers: 'Importar usuarios LDAP',
      testConnection: 'Probar conexión',
      import: 'Importar usuarios',
      save: 'Guardar configuración',
      loadError: 'Error al cargar la configuración de LDAP: {{error}}',
      saveSuccess: 'Configuración de LDAP actualizada correctamente',
      saveError: 'Error al actualizar la configuración de LDAP',
      testError: 'Error al probar la conexión LDAP: {{error}}',
      importSuccess: 'Usuarios LDAP importados correctamente',
      importError: 'Error al importar usuarios LDAP: {{error}}',
      serverUrlRequired: 'Ingrese la URL del servidor LDAP',
      bindDnRequired: 'Ingrese el DN de enlace',
      bindPasswordRequired: 'Ingrese la contraseña de enlace',
      baseDnRequired: 'Ingrese el DN base',
      userFilterRequired: 'Ingrese el filtro de usuario',
      userAttrRequired: 'Ingrese el atributo de usuario',
      emailAttrRequired: 'Ingrese el atributo de correo electrónico',
      displayNameAttrRequired: 'Ingrese el atributo de nombre para mostrar',
      defaultRoleRequired: 'Ingrese el rol predeterminado',
      test: {
        title: 'Probar conexión LDAP',
        username: 'Nombre de usuario',
        password: 'Contraseña',
        test: 'Probar',
        cancel: 'Cancelar',
        usernameRequired: 'Ingrese el nombre de usuario',
        passwordRequired: 'Ingrese la contraseña',
      },
      tlsDivider: 'Configuración de TLS',
      startTls: 'Habilitar TLS',
      insecure: 'No verificar certificado',
      caCert: 'Certificado CA',
      clientCert: 'Certificado de cliente',
      clientCertPlaceholder: 'Ingrese el certificado de cliente',
      clientKey: 'Clave de cliente',
      clientKeyPlaceholder: 'No modificar',
      importTitle: 'Importar usuarios LDAP',
      checkAll: 'Seleccionar todo',
      applicationBaseDn: 'DN base de la aplicación',
      applicationFilter: 'Filtro de aplicación',
      caCertPlaceholder: 'Ingrese el certificado CA',
      importUser: 'Importar usuario',
      importApplication: 'Importar aplicación',
      username: 'Nombre de usuario',
      email: 'Correo electrónico',
      fullName: 'Nombre completo',
      importStatus: 'Estado de importación',
      importTypeBound: 'Vinculado',
      importTypeNew: 'Nuevo',
      applicationBaseDnRequired: 'Ingrese el DN base de la aplicación',
      applicationFilterRequired: 'Ingrese el filtro de aplicación',
    },
  },
}; 