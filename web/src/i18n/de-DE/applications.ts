export default {
  name: 'Anwendungsname',
  description: 'Beschreibung',
  status: 'Status',
  statusEnum: {
    active: 'Aktiv',
    inactive: 'Inaktiv',
    disabled: 'Deaktiviert',
    deleted: 'Gelöscht',
  },
  createdAt: 'Erstellt am',
  updatedAt: 'Aktualisiert am',
  deleteConfirm: 'Sind Sie sicher, dass Sie diese Anwendung löschen möchten?',
  deleteSuccess: 'Erfolgreich gelöscht',
  deleteError: 'Löschen fehlgeschlagen: {{error}}',
  loadError: 'Fehler beim Laden der Anwendungsliste: {{error}}',
  keywordsPlaceholder: 'Anwendungsnamen oder Beschreibung suchen',
  create: 'Anwendung erstellen',
  edit: 'Anwendung bearbeiten',
  view: 'Details anzeigen',
  clientId: 'Client-ID',
  clientSecret: 'Client-Geheimnis',
  redirectUris: 'Weiterleitungs-URIs',
  uri: 'URI',
  icon: 'Symbol',
  grantTypes: 'Gewährungstypen',
  scopes: 'Geltungsbereiche',
  accessTokenValidity: 'Gültigkeit des Zugriffstokens',
  refreshTokenValidity: 'Gültigkeit des Aktualisierungstokens',
  additionalInfo: 'Zusätzliche Informationen',
  save: 'Speichern',
  cancel: 'Abbrechen',
  createSuccess: 'Erfolgreich erstellt',
  createError: 'Erstellen fehlgeschlagen: {{error}}',
  updateSuccess: 'Erfolgreich aktualisiert',
  updateError: 'Aktualisierung fehlgeschlagen: {{error}}',
  scopesPlaceholder: 'Bitte Geltungsbereich auswählen oder eingeben',
  redirectUrisPlaceholder: 'Bitte Weiterleitungs-URI auswählen oder eingeben',
  uriPlaceholder: 'Bitte eine gültige URI eingeben',
  grantTypesPlaceholder: 'Bitte Gewährungstypen auswählen',
  descriptionPlaceholder: 'Bitte Anwendungsbeschreibung eingeben',
  namePlaceholder: 'Bitte Anwendungsnamen eingeben',
  createTitle: 'Anwendung erstellen',
  editTitle: 'Anwendung bearbeiten',
  uriInvalid: 'Bitte eine gültige URI eingeben',
  redirectUrisInvalid: 'Bitte eine gültige Weiterleitungs-URI eingeben',
  nameRequired: 'Bitte Anwendungsnamen eingeben',
  nameInvalid: 'Bitte einen gültigen Anwendungsnamen eingeben (unterstützt nur Zahlen, Buchstaben, Unterstriche und Bindestriche)',
  redirectUrisRequired: 'Bitte eine gültige Weiterleitungs-URI eingeben',
  grantTypesRequired: 'Bitte Gewährungstypen auswählen',
  statusRequired: 'Bitte Status auswählen',
  displayName: 'Anzeigename',
  displayNamePlaceholder: 'Bitte Anzeigenamen der Anwendung eingeben',
  grantType: {
    auto: 'Automatisch',
    authorization_code: 'Autorisierungscode',
    implicit: 'Implizit',
    hybrid: 'Hybrid',
    password: 'Passwort',
    refresh_token: 'Aktualisierungstoken',
  },
  setApplicationPasswordTitle: 'Anwendungsschlüssel setzen',
  setApplicationPasswordDescription: 'Setzen Sie einen Anwendungsschlüssel für den aktuellen Benutzer.',
  currentPassword: 'Aktuelles Passwort',
  setApplicationPasswordSuccess: 'Anwendungsschlüssel erfolgreich gesetzt.',
  passwordNotSet: 'Nicht gesetzt',
  passwordHasBeenSet: 'Passwort gesetzt',
  forceIndependentPassword: 'Anwendungsschlüssel erzwingen',
  forceIndependentPasswordTooltip: 'Wenn aktiviert, müssen Benutzer das Anwendungsschlüssel bei der Authentifizierung verwenden und das Anwendungsschlüssel vor der Verwendung vom Benutzer festgelegt werden.',
  passwordNotSetDescription: 'Die Anwendung erfordert, dass ein Passwort für den aktuellen Benutzer festgelegt wird.',
  independentPassword: 'Anwendungsschlüssel',
  userRemoveConfirm: 'Sind Sie sicher, dass Sie den Benutzer {{user}} löschen möchten?',
  // Anwendungsdetailsseite
  basicInfo: 'Basisinformationen',
  roles: 'Rollen',
  accessKeys: 'Zugriffsschlüssel',
  issuerKeys: 'Ausstellerschlüssel',
  users: 'Benutzer',
  createRole: 'Rolle erstellen',
  createKey: 'Schlüssel erstellen',
  refresh: 'Aktualisieren',
  keyCountLimitReached: 'Anzahl der Schlüssel überschritten',
  roleName: 'Rollenname',
  roleDescription: 'Rollenbeschreibung',
  roleCreatedAt: 'Erstellt am',
  keyName: 'Schlüsselname',
  keyValue: 'Schlüsselwert',
  keyExpiresAt: 'Gültig bis',
  createKeySuccess: 'Schlüssel erfolgreich erstellt',
  keyCreatedAt: 'Erstellt am',
  keyNeverExpires: 'Läuft nie ab',
  keyCreateSuccess: 'Schlüssel erfolgreich erstellt',
  keyCreateError: 'Fehler beim Erstellen des Schlüssels: {{error}}',
  keyDeleteSuccess: 'Schlüssel erfolgreich gelöscht',
  keyDeleteError: 'Fehler beim Löschen des Schlüssels: {{error}}',
  newKeyDescription: 'Bitte speichern Sie die folgenden Informationen, der Schlüssel wird nur einmal angezeigt',
  keyNameRequired: 'Bitte Schlüsselnamen eingeben',
  keyNamePlaceholder: 'Bitte Schlüsselnamen eingeben',
  roleCreateSuccess: 'Rolle erfolgreich erstellt',
  roleCreateError: 'Fehler beim Erstellen der Rolle: {{error}}',
  roleUpdateSuccess: 'Rolle erfolgreich aktualisiert',
  roleUpdateError: 'Fehler beim Aktualisieren der Rolle: {{error}}',
  roleNameRequired: 'Bitte Rollennamen eingeben',
  roleNamePlaceholder: 'Bitte Rollennamen eingeben',
  roleDescriptionPlaceholder: 'Bitte Rollenbeschreibung eingeben',
  assignUser: 'Benutzer zuweisen',
  selectUser: 'Benutzer auswählen',
  selectRoles: 'Rollen auswählen',
  userRequired: 'Bitte Benutzer auswählen',
  rolesRequired: 'Bitte Rollen auswählen',
  selectUserPlaceholder: 'Bitte Benutzer auswählen',
  selectRolesPlaceholder: 'Bitte Rollen auswählen',
  userAssignSuccess: 'Benutzer erfolgreich zugewiesen',
  userAssignError: 'Fehler beim Zuweisen des Benutzers: {{error}}',
  userRemoveSuccess: 'Benutzer erfolgreich entfernt',
  userRemoveError: 'Fehler beim Entfernen des Benutzers: {{error}}',
  userName: 'Benutzername',
  userEmail: 'E-Mail',
  userRoles: 'Rollen',
  noRole: 'Keine Rolle',
  backToList: 'Zurück zur Liste',
  editRole: 'Rolle bearbeiten',
  deleteRole: 'Rolle löschen',
  deleteRoleConfirm: 'Sind Sie sicher, dass Sie die Rolle {{role}} löschen möchten?',
  deleteRoleSuccess: 'Rolle erfolgreich gelöscht',
  deleteRoleError: 'Fehler beim Löschen der Rolle: {{error}}',
  deleteKeyConfirm: 'Sind Sie sicher, dass Sie den Schlüssel {{name}} löschen möchten?',
  deleteKeySuccess: 'Schlüssel erfolgreich gelöscht',
  deleteKeyError: 'Fehler beim Löschen des Schlüssels: {{error}}',
  systemAttr: 'System',

  keySource: 'Schlüsselquelle',
  keyPrivateKeyImport: 'Importieren',
  keyPrivateKeyAutoGenerate: 'Automatisch generieren',
  keyPrivateKey: 'Privater Schlüssel',
  keyAlgorithm: 'Algorithmus',
  keyPrivateKeyRequired: 'Privater Schlüssel erforderlich',
  keyAlgorithmRequired: 'Algorithmus erforderlich',
  createIssuerKey: 'Ausstellerschlüssel erstellen',
  keyAlgorithmRSA: 'RSA',
  keyAlgorithmECDSA: 'ECDSA',
  keyAlgorithmHMAC: 'HMAC',
  keyAlgorithmRS256: 'RS256',
  keyAlgorithmRS384: 'RS384',
  keyAlgorithmRS512: 'RS512',
  keyAlgorithmES256: 'ES256',
  keyAlgorithmES384: 'ES384',
  keyAlgorithmES512: 'ES512',
  keyAlgorithmHS256: 'HS256',
  keyAlgorithmHS384: 'HS384',
  keyAlgorithmHS512: 'HS512',
  keyPrivateKeyTooltip: {
    RS256: 'Der RS512-Algorithmus erfordert eine RSA-Schlüssellänge von 2048. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    RS384: 'Der RS384-Algorithmus erfordert eine RSA-Schlüssellänge von 3072. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    RS512: 'Der RS512-Algorithmus erfordert eine RSA-Schlüssellänge von 4096. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    ES256: 'Der ES256-Algorithmus erfordert den elliptischen Kurvenparameter secp256k1. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    ES384: 'Der ES384-Algorithmus erfordert den elliptischen Kurvenparameter secp384k1. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    ES512: 'Der ES512-Algorithmus erfordert den elliptischen Kurvenparameter secp521k1. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    HS256: 'Der HS256-Algorithmus erfordert einen base64-kodierten Schlüssel. Die Schlüssellänge ist nicht begrenzt, es wird jedoch empfohlen, einen 256-Bit- (32-Byte) oder längeren Schlüssel zu verwenden. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    HS384: 'Der HS384-Algorithmus erfordert einen base64-kodierten Schlüssel. Die Schlüssellänge ist nicht begrenzt, es wird jedoch empfohlen, einen 384-Bit- (48-Byte) oder längeren Schlüssel zu verwenden. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
    HS512: 'Der HS512-Algorithmus erfordert einen base64-kodierten Schlüssel. Die Schlüssellänge ist nicht begrenzt, es wird jedoch empfohlen, einen 512-Bit- (64-Byte) oder längeren Schlüssel zu verwenden. Sie können den folgenden Befehl verwenden, um einen neuen Schlüssel zu generieren:',
  },
  keyPrivateKeyTooltipCommand: {
    RS256: 'openssl genrsa 2048',
    RS384: 'openssl genrsa 3072',
    RS512: 'openssl genrsa 4096',
    ES256: 'openssl ecparam -name secp256k1 -genkey',
    ES384: 'openssl ecparam -name secp384k1 -genkey',
    ES512: 'openssl ecparam -name secp521k1 -genkey',
    HS256: 'openssl rand -base64 32',
    HS384: 'openssl rand -base64 48',
    HS512: 'openssl rand -base64 64',
  },
  deleteIssuerKeySuccess: 'Ausstellerschlüssel erfolgreich gelöscht',
  deleteIssuerKeyError: 'Fehler beim Löschen des Ausstellerschlüssels: {{error}}',
  gotoTest: 'Zum Testen gehen',
  setApplicationPasswordError: {
    E40050: 'Das Passwort muss mindestens {{minLength}} Zeichen lang sein',
    E40051: 'Das Passwort muss mindestens zwei Kombinationen aus Großbuchstaben, Kleinbuchstaben und Zahlen enthalten',
    E40052: 'Das Passwort muss Großbuchstaben, Kleinbuchstaben und Zahlen enthalten',
    E40053: 'Das Passwort muss Großbuchstaben, Kleinbuchstaben, Zahlen und Sonderzeichen enthalten',
  },
}; 