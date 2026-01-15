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
	"time"

	"github.com/sven-victor/ez-console/pkg/model"
)

var UserStatusInvalidLDAPBinding = "invalid_ldap_binding"

type User struct {
	model.Base
	Username          string           `gorm:"uniqueIndex;size:50;not null" json:"username"`
	Email             string           `gorm:"uniqueIndex;size:100;not null" json:"email"`
	FullName          string           `gorm:"size:100;not null" json:"full_name"`
	Password          string           `gorm:"size:255;not null" json:"-"`
	Salt              string           `gorm:"size:32;not null" json:"-"`
	Phone             string           `gorm:"size:20" json:"phone,omitempty"`
	Avatar            string           `gorm:"size:255" json:"avatar,omitempty"`
	Status            string           `gorm:"size:20;not null;default:'active'" json:"status"`
	MFAEnabled        bool             `gorm:"default:false" json:"mfa_enabled"`
	LDAPDN            string           `gorm:"column:ldap_dn;size:255" json:"ldap_dn,omitempty"`
	MFAEnforced       bool             `gorm:"default:false" json:"mfa_enforced"`
	Source            model.UserSource `gorm:"size:20;not null;default:'local'" json:"source,omitempty"`
	LDAPAttrs         []LDAPAttr       `gorm:"-" json:"ldap_attrs"`
	Roles             []model.Role     `gorm:"many2many:user_roles;" json:"roles"`
	Role              string           `gorm:"<-:false" json:"role"`
	RoleID            string           `gorm:"<-:false" json:"role_id"`
	LockedUntil       time.Time        `json:"-"`
	PasswordChangedAt time.Time        `json:"-"`
	LastLogin         time.Time        `json:"last_login,omitempty"`
}

// IsPasswordExpired checks if the password has expired
func (u *User) IsPasswordExpired(expiryDays int) bool {
	if expiryDays <= 0 {
		return false
	}

	expiryTime := u.PasswordChangedAt.AddDate(0, 0, expiryDays)
	return time.Now().After(expiryTime)
}

// IsLocked checks if the account is locked
func (u *User) IsLocked() bool {
	return time.Now().Before(u.LockedUntil)
}

func (u *User) IsDeleted() bool {
	return u.DeletedAt.Valid && !u.DeletedAt.Time.IsZero()
}
