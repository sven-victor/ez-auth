// Copyright 2026 Sven Victor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	clientsldap "github.com/sven-victor/ez-console/pkg/clients/ldap"
	"github.com/sven-victor/ez-console/pkg/model"
)

type LDAPApplicationSettings struct {
	ApplicationLDAPEnabled bool   `json:"application_ldap_enabled"`
	ApplicationBaseDN      string `json:"application_base_dn"`
	ApplicationFilter      string `json:"application_filter"`
	ApplicationObjectClass string `json:"application_object_class"`
}

type LDAPSettings struct {
	clientsldap.Options
	LDAPApplicationSettings
}

const (
	SettingLDAPApplicationLDAPEnabled = "ldap_application_ldap_enabled"
	SettingLDAPApplicationBaseDN      = "ldap_application_base_dn"
	SettingLDAPApplicationFilter      = "ldap_application_filter"
	SettingLDAPApplicationObjectClass = "ldap_application_object_class"
)

var LDAPApplicationSettingKeys = []model.SettingKey{
	SettingLDAPApplicationLDAPEnabled,
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
