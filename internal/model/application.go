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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sven-victor/ez-console/pkg/db"
	"github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-utils/safe"
)

type ApplicationKey struct {
	model.Base
	Name          string      `gorm:"type:varchar(255);not null;default:''" json:"name"`
	ExpiresAt     *time.Time  `gorm:"type:datetime" json:"expires_at"`
	ApplicationID string      `gorm:"type:varchar(36);not null" json:"application_id"`
	ClientID      string      `gorm:"type:varchar(255);not null" json:"client_id"`
	ClientSecret  safe.String `gorm:"type:varchar(255);not null" json:"-"`
}

type ApplicationGrantType string

const (
	ApplicationGrantTypeAuto              ApplicationGrantType = "auto"
	ApplicationGrantTypeAuthorizationCode ApplicationGrantType = "authorization_code"
	ApplicationGrantTypeImplicit          ApplicationGrantType = "implicit"
	ApplicationGrantTypeHybrid            ApplicationGrantType = "hybrid"
	ApplicationGrantTypeRefreshToken      ApplicationGrantType = "refresh_token"
	ApplicationGrantTypePassword          ApplicationGrantType = "password"
)

// Application Application model
type Application struct {
	model.Base
	Name            string            `gorm:"type:varchar(100);not null" json:"name"`
	DisplayName     string            `gorm:"type:varchar(100);" json:"display_name"`
	DisplayNameI18n map[string]string `gorm:"serializer:json" json:"display_name_i18n,omitempty"`
	Description     string            `gorm:"type:varchar(500)" json:"description"`
	DescriptionI18n map[string]string `gorm:"serializer:json" json:"description_i18n,omitempty"`
	Icon            string            `gorm:"type:varchar(500)" json:"icon"`
	Status          string            `gorm:"type:varchar(20);not null;default:'active'" json:"status"` // active, inactive
	Source          string            `gorm:"type:varchar(20);not null;default:'ldap'" json:"source"`   // ldap, local
	LDAPDN          string            `gorm:"column:ldap_dn;size:255" json:"ldap_dn,omitempty"`
	URI             string            `gorm:"type:varchar(500)" json:"uri,omitempty"`
	GrantTypes      []string          `gorm:"type:varchar(255);serializer:json" json:"grant_types,omitempty"`
	RedirectUris    []string          `gorm:"type:varchar(255);serializer:json" json:"redirect_uris,omitempty"`
	Scopes          []string          `gorm:"type:varchar(255);serializer:json" json:"scopes,omitempty"`
	Roles           []ApplicationRole `gorm:"-" json:"roles,omitempty"`
	Users           []User            `gorm:"-" json:"users,omitempty"`
	LDAPAttrs       []LDAPAttr        `gorm:"-" json:"ldap_attrs,omitempty"`

	ForceIndependentPassword bool   `gorm:"type:tinyint(1);not null;default:0" json:"force_independent_password"`
	OrganizationID           string `gorm:"type:varchar(36);index;default:'00000000000000000000000000000000'" json:"organization_id,omitempty"`
}

func (a *Application) CheckRedirectURI(uri string) bool {
	if len(a.RedirectUris) > 0 {
		for _, redirectURI := range a.RedirectUris {
			if strings.HasPrefix(uri, redirectURI) {
				return true
			}
		}
	}
	return false
}

type UserApplication struct {
	model.Base
	Name                     string            `gorm:"type:varchar(100);not null" json:"name"`
	DisplayName              string            `gorm:"type:varchar(100);" json:"display_name"`
	DisplayNameI18n          map[string]string `gorm:"serializer:json" json:"display_name_i18n,omitempty"`
	Description              string            `gorm:"type:varchar(500)" json:"description"`
	DescriptionI18n          map[string]string `gorm:"serializer:json" json:"description_i18n,omitempty"`
	Icon                     string            `gorm:"type:varchar(500)" json:"icon"`
	Status                   string            `gorm:"type:varchar(20);not null;default:'active'" json:"status"` // active, inactive
	Source                   string            `gorm:"type:varchar(20);not null;default:'ldap'" json:"source"`   // ldap, local
	LDAPDN                   string            `gorm:"column:ldap_dn;size:255" json:"ldap_dn,omitempty"`
	URI                      string            `gorm:"type:varchar(500)" json:"uri,omitempty"`
	GrantTypes               []string          `gorm:"type:varchar(255);serializer:json" json:"grant_types,omitempty"`
	RedirectUris             []string          `gorm:"type:varchar(255);serializer:json" json:"redirect_uris,omitempty"`
	Scopes                   []string          `gorm:"type:varchar(255);serializer:json" json:"scopes,omitempty"`
	Role                     string            `gorm:"type:varchar(100)" json:"role"`
	RoleDescription          string            `gorm:"type:varchar(500)" json:"role_description"`
	ForceIndependentPassword bool              `gorm:"type:tinyint(1);not null;default:0" json:"force_independent_password"`
	Password                 string            `gorm:"type:varchar(255)" json:"-"`
	HasPassword              *bool             `gorm:"-" json:"has_password,omitempty"`
	OrganizationID           string            `gorm:"type:varchar(36);index;default:'00000000000000000000000000000000'" json:"organization_id,omitempty"`
	OrganizationName         string            `gorm:"type:varchar(100)" json:"organization_name"`
}

type ApplicationPrivateKey struct {
	model.Base
	Name          string      `gorm:"type:varchar(255);not null;default:''" json:"name"`
	ApplicationID string      `gorm:"type:varchar(36);not null" json:"application_id"`
	Algorithm     string      `gorm:"type:varchar(20);not null" json:"algorithm"`
	PrivateKey    safe.String `gorm:"type:text;not null" json:"private_key"`
	privateKey    any
}

func (key *ApplicationPrivateKey) SetPrivateKey(privateKey any) {
	key.privateKey = privateKey
}

func privateKeyParser(privateKey string, factory func([]byte) (any, error)) (any, error) {
	// Check if it's in PEM format
	if strings.HasPrefix(privateKey, "-----BEGIN") {
		block, _ := pem.Decode([]byte(privateKey))
		if block == nil {
			return nil, fmt.Errorf("invalid pem format")
		}
		return factory(block.Bytes)
	}
	{
		encoding := base64.StdEncoding
		if strings.ContainsAny(privateKey, "-_") {
			encoding = base64.URLEncoding
		}
		if len(privateKey)%4 != 0 {
			encoding = encoding.WithPadding(base64.NoPadding)
		}
		// Try base64 decoding
		decoded, err := encoding.DecodeString(privateKey)
		if err == nil {
			if strings.HasPrefix(string(decoded), "-----BEGIN") {
				block, _ := pem.Decode(decoded)
				if block == nil {
					return nil, fmt.Errorf("invalid pem base64 format")
				}
				return factory(block.Bytes)
			}
			return factory(decoded)
		}
	}
	return factory([]byte(privateKey))
}

func ParsePrivateKey(privateKey string, algorithm string) (any, error) {
	switch algorithm {
	case "RS256", "RS384", "RS512":
		return privateKeyParser(privateKey, func(der []byte) (any, error) {
			pk, err := x509.ParsePKCS1PrivateKey(der)
			if err != nil && strings.Contains(err.Error(), "ParsePKCS8PrivateKey") {
				return x509.ParsePKCS8PrivateKey(der)
			}
			return pk, err
		})
	case "ES256", "ES384", "ES512":
		return privateKeyParser(privateKey, func(der []byte) (any, error) {
			pk, err := x509.ParseECPrivateKey(der)
			if err != nil {
				if strings.Contains(err.Error(), "ParsePKCS8PrivateKey") {
					return x509.ParsePKCS8PrivateKey(der)
				}
				if strings.Contains(err.Error(), "ParsePKCS1PrivateKey") {
					return x509.ParsePKCS1PrivateKey(der)
				}
				return nil, err
			}
			return pk, nil
		})
	case "HS256", "HS384", "HS512":
		decoded, err := base64.StdEncoding.DecodeString(privateKey)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

// GetPrivateKey Get private key, if private key is not parsed, parse it
func (a *ApplicationPrivateKey) GetPrivateKey() (any, error) {
	if a.privateKey == nil {
		pk, err := a.PrivateKey.UnsafeString()
		if err != nil {
			return nil, err
		}
		fmt.Println("pk", pk)
		parsed, err := ParsePrivateKey(pk, a.Algorithm)
		if err != nil {
			return nil, err
		}
		a.privateKey = parsed
	}
	return a.privateKey, nil
}

var SigningMethodMap = map[string]jwt.SigningMethod{
	"RS256": jwt.SigningMethodRS256,
	"RS384": jwt.SigningMethodRS384,
	"RS512": jwt.SigningMethodRS512,
	"ES256": jwt.SigningMethodES256,
	"ES384": jwt.SigningMethodES384,
	"ES512": jwt.SigningMethodES512,
	"HS256": jwt.SigningMethodHS256,
	"HS384": jwt.SigningMethodHS384,
	"HS512": jwt.SigningMethodHS512,
}

func (a *ApplicationPrivateKey) GetAlgorithm() jwt.SigningMethod {
	return SigningMethodMap[a.Algorithm]
}

// ApplicationRole Application role model
type ApplicationRole struct {
	model.Base
	ApplicationID string `gorm:"type:varchar(36);not null" json:"application_id"`
	Name          string `gorm:"type:varchar(100);not null" json:"name"`
	Description   string `gorm:"type:varchar(500)" json:"description"`
}

// ApplicationUser Application user association model
type ApplicationUser struct {
	model.Base
	ApplicationID string `gorm:"type:varchar(36);not null" json:"application_id"`
	UserID        string `gorm:"type:varchar(36);not null" json:"user_id"`
	RoleID        string `gorm:"type:varchar(36)" json:"role_id"`
	Password      string `gorm:"type:varchar(255)" json:"-"`
}

type ApplicationAuthorization struct {
	model.Base
	ApplicationID string       `gorm:"type:varchar(36);not null" json:"application_id"`
	Application   *Application `gorm:"foreignKey:ApplicationID" json:"application,omitempty"`
	UserID        string       `gorm:"type:varchar(36);not null" json:"user_id"`
	Scopes        []string     `gorm:"type:varchar(255);serializer:json" json:"scopes"`
}

func init() {
	db.RegisterModels(
		&Application{},
		&ApplicationRole{},
		&ApplicationUser{},
		&ApplicationKey{},
		&ApplicationPrivateKey{},
		&ApplicationAuthorization{},
	)
}
