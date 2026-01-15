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

import applications from './sv-SE/applications';
import common from './sv-SE/common';
import oidc from './sv-SE/oidc';
import system from './sv-SE/system';
import users from './sv-SE/users';

export default {
  ...common,
  ...system,
  ...users,
  ...applications,
  ...oidc,
  breadcrumbs: {
    home: 'Hem',
    ldap_settings: 'LDAP-inställningar',
    application_management: 'Applikationshantering',
    user_management: 'Användarhantering',
    settings: 'Inställningar',
    system_settings: 'Systeminställningar',
  },
  menu: {
    home: 'Hem',
    ldap_settings: 'LDAP-inställningar',
    application_management: 'Applikationshantering',
    user_management: 'Användarhantering',
    settings: 'Inställningar',
    console: 'Konsol',
    dashboard: 'Dashboard',
  },
}; 