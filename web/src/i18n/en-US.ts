import common from './en-US/common';
import users from './en-US/users';
import applications from './en-US/applications';
import oidc from './en-US/oidc';
import system from './en-US/system';

export default {
  ...common,
  ...users,
  ...applications,
  ...oidc,
  ...system,
  breadcrumbs: {
    home: 'Home',
    ldap_settings: 'LDAP Settings',
    application_management: 'Application Management',
    user_management: 'User Management',
    settings: 'Settings',
    system_settings: 'System Settings',
  },
  menu: {
    home: 'Home',
    ldap_settings: 'LDAP Settings',
    application_management: 'Application Management',
    user_management: 'User Management',
    settings: 'Settings',
    console: 'Console',
    dashboard: 'Dashboard',
  },
}; 