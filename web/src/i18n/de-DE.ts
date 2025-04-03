import applications from './de-DE/applications';
import common from './de-DE/common';
import oidc from './de-DE/oidc';
import system from './de-DE/system';
import users from './de-DE/users';

export default {
  ...common,
  ...system,
  ...users,
  ...applications,
  ...oidc,
  breadcrumbs: {
    home: 'Startseite',
    ldap_settings: 'LDAP-Einstellungen',
    application_management: 'Anwendungsmanagementsystem',
    user_management: 'Benutzerverwaltung',
    settings: 'Einstellungen',
    system_settings: 'Systemeinstellungen',
  },
  menu: {
    home: 'Startseite',
    ldap_settings: 'LDAP-Einstellungen',
    application_management: 'Anwendungsmanagementsystem',
    user_management: 'Benutzerverwaltung',
    settings: 'Einstellungen',
    console: 'Konsole',
    dashboard: 'Dashboard',
  },
}; 