package model

import (
	clientsldap "github.com/sven-victor/ez-console/pkg/clients/ldap"
	"github.com/sven-victor/ez-console/pkg/model"
)

type LDAPApplicationSettings struct {
	ApplicationBaseDN      string `json:"application_base_dn"`
	ApplicationFilter      string `json:"application_filter"`
	ApplicationObjectClass string `json:"application_object_class"`
}

type LDAPSettings struct {
	clientsldap.Options
	LDAPApplicationSettings
}

const (
	SettingLDAPApplicationBaseDN      = "ldap_application_base_dn"
	SettingLDAPApplicationFilter      = "ldap_application_filter"
	SettingLDAPApplicationObjectClass = "ldap_application_object_class"
)

var LDAPApplicationSettingKeys = []model.SettingKey{
	SettingLDAPApplicationBaseDN,
	SettingLDAPApplicationFilter,
	SettingLDAPApplicationObjectClass,
}

func init() {
	model.RegisterSettingKeys("ldap", LDAPApplicationSettings{}, LDAPApplicationSettingKeys...)
}

type LDAPAttr struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	UserAttr bool   `json:"user_attr"`
}
