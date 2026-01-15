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


import applications from './ar-AE/applications';
import common from './ar-AE/common';
import oidc from './ar-AE/oidc';
import system from './ar-AE/system';
import users from './ar-AE/users';

export default {
  ...common,
  ...system,
  ...users,
  ...applications,
  ...oidc,
  breadcrumbs: {
    home: 'الرئيسية',
    ldap_settings: 'إعدادات LDAP',
    application_management: 'إدارة التطبيقات',
    user_management: 'إدارة المستخدمين',
    settings: 'الإعدادات',
    system_settings: 'إعدادات النظام',
  },
  menu: {
    home: 'الرئيسية',
    ldap_settings: 'إعدادات LDAP',
    application_management: 'إدارة التطبيقات',
    user_management: 'إدارة المستخدمين',
    settings: 'الإعدادات',
    console: 'المحطة',
    dashboard: 'لوحة التحكم',
  },
}; 