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