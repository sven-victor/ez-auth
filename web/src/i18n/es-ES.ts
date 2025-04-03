import applications from './es-ES/applications';
import common from './es-ES/common';
import oidc from './es-ES/oidc';
import system from './es-ES/system';
import users from './es-ES/users';

export default {
  ...common,
  ...system,
  ...users,
  ...applications,
  ...oidc,
  breadcrumbs: {
    home: 'Inicio',
    ldap_settings: 'Configuración LDAP',
    application_management: 'Gestión de aplicaciones',
    user_management: 'Gestión de usuarios',
    settings: 'Configuración',
    system_settings: 'Configuración del sistema',
  },
  menu: {
    home: 'Inicio',
    ldap_settings: 'Configuración LDAP',
    application_management: 'Gestión de aplicaciones',
    user_management: 'Gestión de usuarios',
    settings: 'Configuración',
    console: 'Consola',
    dashboard: 'Dashboard',
  },
}; 