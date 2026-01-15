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

import applications from './fr-FR/applications';
import common from './fr-FR/common';
import oidc from './fr-FR/oidc';
import system from './fr-FR/system';
import users from './fr-FR/users';

export default {
  ...common,
  ...system,
  ...users,
  ...applications,
  ...oidc,
  breadcrumbs: {
    home: 'Accueil',
    ldap_settings: 'Paramètres LDAP',
    application_management: 'Gestion des applications',
    user_management: 'Gestion des utilisateurs',
    settings: 'Paramètres',
    system_settings: 'Paramètres du système',
  },
  menu: {
    home: 'Accueil',
    ldap_settings: 'Paramètres LDAP',
    application_management: 'Gestion des applications',
    user_management: 'Gestion des utilisateurs',
    settings: 'Paramètres',
    console: 'Console',
    dashboard: 'Tableau de bord',
  },
}; 