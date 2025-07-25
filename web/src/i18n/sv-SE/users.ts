export default {
  // User List Page
  username: 'Användarnamn',
  fullName: 'Fullständigt namn',
  email: 'E-post',
  source: 'Källa',
  sourceLdap: 'LDAP',
  sourceAll: 'Alla',
  sourceOauth2: 'OAuth2',
  ldapUserNotBound: 'LDAP-användare är inte bunden till någon lokal användare, vänligen bind den.',
  invalidLdapBindingRelationship: 'Ogiltig LDAP-bindningsrelation: {{ldap_dn}}',
  ldapUserDNNotSet: 'LDAP-användar-DN är inte inställt, vänligen ställ in det.',
  localUserLDAPDNSet: 'LDAP-användar-DN är inställt, men användaren är inte en LDAP-användare, vänligen korrigera det.',
  updateUserSuccess: 'Användaren har uppdaterats',
  updateUserError: 'Kunde inte uppdatera användaren: {{error}}',
  sourceLocal: 'Lokal',
  status: 'Status',
  statusEnum: {
    active: 'Aktiv',
    disabled: 'Inaktiverad',
    locked: 'Låst',
    password_expired: 'Lösenordet har gått ut',
    deleted: 'Raderad',
    invalid_ldap_binding: 'Ogiltig LDAP-bindning',
  },
  roles: 'Roller',
  noRole: 'Ingen roll',
  mfa: 'MFA',
  mfaEnabled: 'Aktiverad',
  mfaDisabled: 'Inaktiverad',
  lastLogin: 'Senaste inloggning',
  neverLogin: 'Aldrig',
  viewDetail: 'Visa detaljer',
  edit: 'Redigera',
  delete: 'Radera',
  resetPassword: 'Återställ lösenord',
  resetPasswordTitle: 'Återställ lösenord',
  resetPasswordConfirm: 'Är du säker på att du vill återställa lösenordet för användare {{username}}?',
  resetPasswordSuccess: 'Lösenordet har återställts',
  resetPasswordSuccessContent: 'Nytt lösenord: {{password}}',
  resetPasswordError: 'Kunde inte återställa lösenordet: {{error}}',
  deleteSuccess: 'Radering lyckades',
  deleteError: 'Kunde inte radera: {{error}}',
  loadError: 'Kunde inte ladda användarlistan: {{error}}',
  statusPlaceholder: 'Välj status',
  keywordsPlaceholder: 'Sök användarnamn/e-post',
  deleteConfirm: 'Är du säker på att du vill radera användare {{username}}?',
  // User Form
  createTitle: 'Skapa användare',
  editTitle: 'Redigera användare',
  nameRequired: 'Ange fullständigt namn',
  usernameRequired: 'Ange användarnamn',
  emailRequired: 'Ange e-post',
  emailInvalid: 'Ange en giltig e-postadress',
  passwordRequired: 'Ange lösenord',
  passwordConfirmRequired: 'Bekräfta lösenord',
  passwordMismatch: 'Lösenorden matchar inte',
  passwordPlaceholder: 'Ange lösenord',
  passwordConfirmPlaceholder: 'Bekräfta lösenord',
  usernamePlaceholder: 'Ange användarnamn',
  emailPlaceholder: 'Ange e-post',
  namePlaceholder: 'Ange fullständigt namn',
  rolePlaceholder: 'Välj roll',
  statusRequired: 'Välj status',
  // User Detail
  basicInfo: 'Grundläggande information',
  security: 'Säkerhetsinställningar',
  permissions: 'Behörigheter',
  lastLoginTime: 'Senaste inloggningstid',
  lastLoginIp: 'Senaste inloggnings-IP',
  loginHistory: 'Inloggningshistorik',
  mfaSettings: 'MFA-inställningar',
  enableMfa: 'Aktivera MFA',
  disableMfa: 'Inaktivera MFA',
  mfaEnabledSuccess: 'MFA aktiverad',
  mfaDisabledSuccess: 'MFA inaktiverad',
  mfaEnableError: 'Kunde inte aktivera MFA: {{error}}',
  mfaDisableError: 'Kunde inte inaktivera MFA: {{error}}',
  // Common
  back: 'Tillbaka',
  save: 'Spara',
  cancel: 'Avbryt',
  confirm: 'Bekräfta',
  search: 'Sök',
  reset: 'Återställ',
  refresh: 'Uppdatera',
  updatedAt: 'Uppdaterad den',
  createdAt: 'Skapad den',
  backToList: 'Tillbaka till listan',
  notFound: 'Användaren hittades inte',

  fixUser: 'Fixa användare',
  fixUserBindLDAPUser: 'Bind LDAP-användare',
  fixUserConvertToLocal: 'Konvertera till lokal',
  fixUserTitle: 'Fixa användare',
  keywords: 'Sök efter användarnamn, fullständigt namn eller e-post',
  restore: 'Återställ',
  restoreConfirm: 'Är du säker på att du vill återställa den här användaren?',
  sourceALL: 'ALLA',
  unlock: 'Lås upp',
  unlockConfirm: 'Är du säker på att du vill låsa upp den här användaren?',
  unlockTitle: 'Lås upp användare',
  unlockSuccess: 'Användare upplåst',
  unlockError: 'Kunde inte låsa upp användare: {{error}}',

  assignApplication: 'Tilldela applikation',
  selectApplication: 'Välj applikation',
  selectApplicationPlaceholder: 'Välj applikation',
  applicationRequired: 'Välj applikation',
  createUser: 'Skapa användare',
  assignedApplications: 'Tilldelade applikationer',
  selectRolesPlaceholder: 'Välj roller',
  systemAttr: 'System',
  avatar: 'Avatar',
  fullNameRequired: 'Ange fullständigt namn',
  fullNamePlaceholder: 'Ange fullständigt namn',
  applicationRemoveSuccess: 'Applikationen har tagits bort',
  applicationRemoveError: 'Kunde inte ta bort applikationen: {{error}}',
  applicationRemoveConfirm: 'Är du säker på att du vill ta bort applikationen {{application}} från användaren?',
}; 