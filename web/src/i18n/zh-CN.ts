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

import common from './zh-CN/common';
import users from './zh-CN/users';
import applications from './zh-CN/applications';
import oidc from './zh-CN/oidc';
import system from './zh-CN/system';

export default {
  ...common,
  ...users,
  ...applications,
  ...oidc,
  ...system,
  breadcrumbs: {
    home: '首页',
    ldap_settings: 'LDAP设置',
    application_management: '应用管理',
    user_management: '用户管理',
    settings: '设置',
    system_settings: '系统设置',
  },
  menu: {
    home: '首页',
    ldap_settings: 'LDAP设置',
    application_management: '应用管理',
    user_management: '用户管理',
    settings: '设置',
    console: '控制台',
  },
}; 