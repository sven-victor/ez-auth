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