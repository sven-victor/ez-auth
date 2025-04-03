
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