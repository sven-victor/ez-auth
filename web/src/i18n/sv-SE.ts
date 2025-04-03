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