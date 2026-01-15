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

import applications from './es-ES/applications';
import common from './es-ES/common';
import oidc from './es-ES/oidc';
import system from './es-ES/system';
import users from './es-ES/users';

export default {
  ...common,
  ...system,
  ...users,
  ...applications,
  ...oidc,
  breadcrumbs: {
    home: 'Inicio',
    ldap_settings: 'Configuración LDAP',
    application_management: 'Gestión de aplicaciones',
    user_management: 'Gestión de usuarios',
    settings: 'Configuración',
    system_settings: 'Configuración del sistema',
  },
  menu: {
    home: 'Inicio',
    ldap_settings: 'Configuración LDAP',
    application_management: 'Gestión de aplicaciones',
    user_management: 'Gestión de usuarios',
    settings: 'Configuración',
    console: 'Consola',
    dashboard: 'Dashboard',
  },
}; 