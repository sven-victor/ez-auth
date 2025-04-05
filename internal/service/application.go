package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	"github.com/sven-victor/ez-auth/internal/model"
	"github.com/sven-victor/ez-console/pkg/db"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-console/pkg/util"
	jwtutil "github.com/sven-victor/ez-console/pkg/util/jwt"
	"github.com/sven-victor/ez-console/server"
	"github.com/sven-victor/ez-utils/log"
	"github.com/sven-victor/ez-utils/safe"
	w "github.com/sven-victor/ez-utils/wrapper"
	"gorm.io/gorm"
)

type ApplicationService struct {
	BaseService
}

func NewApplicationService(svc server.Service) *ApplicationService {
	return &ApplicationService{
		BaseService: BaseService{Service: svc},
	}
}

// CreateApplication creates a new application
func (s *ApplicationService) CreateApplication(ctx context.Context, app *model.Application) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	applicationObjectClass, err := s.GetStringSetting(ctx, model.SettingLDAPApplicationObjectClass, "groupOfNames")
	if err != nil {
		return fmt.Errorf("failed to get LDAP application object class: %w", err)
	}

	baseDN, err := s.GetStringSetting(ctx, model.SettingLDAPApplicationBaseDN, "")
	if err != nil {
		return fmt.Errorf("failed to get LDAP application base DN: %w", err)
	}
	if len(baseDN) == 0 {
		return fmt.Errorf("LDAP application base DN is empty")
	}
	dn := fmt.Sprintf("cn=%s,%s", app.Name, baseDN)
	var addRequest *ldap.AddRequest

	if len(app.LDAPAttrs) > 0 {
		addRequest = ldap.NewAddRequest(dn, nil)
		entryAttrs := map[string][]string{}
		for _, attr := range app.LDAPAttrs {
			if attr.Name == "cn" {
				app.Name = attr.Value
			}
			if _, ok := entryAttrs[attr.Name]; !ok {
				entryAttrs[attr.Name] = []string{attr.Value}
			} else {
				entryAttrs[attr.Name] = append(entryAttrs[attr.Name], attr.Value)
			}
		}
		if cn, ok := entryAttrs["cn"]; !ok || len(cn) == 0 || app.Name == "" {
			return fmt.Errorf("application name is empty")
		}
		for name, attr := range entryAttrs {
			addRequest.Attribute(name, attr)
		}
		addRequest.DN = fmt.Sprintf("cn=%s,%s", app.Name, baseDN)
		app.LDAPDN = addRequest.DN
	} else {
		if len(app.Users) > 0 {
			addRequest = ldap.NewAddRequest(dn, nil)
			addRequest.Attribute("cn", []string{app.Name})
			addRequest.Attribute("objectClass", []string{"top", applicationObjectClass})
			userDNs := w.Filter(w.Map(app.Users, func(user model.User) string {
				return user.LDAPDN
			}), func(dn string) bool {
				return len(dn) > 0
			})
			if applicationObjectClass == "groupOfUniqueNames" {
				addRequest.Attribute("uniqueMember", userDNs)
			} else {
				addRequest.Attribute("member", userDNs)
			}
			app.LDAPDN = dn
		}
	}

	// Create database record
	return db.Session(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Error; err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		if err := tx.Find(&model.Application{}).Where("name = ?", app.Name).First(&model.Application{}).Error; err != nil {
			if err != gorm.ErrRecordNotFound {
				return fmt.Errorf("failed to check if application exists: %w", err)
			}
		} else {
			return fmt.Errorf("application already exists")
		}
		if err := tx.Create(app).Error; err != nil {
			return fmt.Errorf("failed to create application: %w", err)
		}

		if len(app.Roles) > 0 {
			for i := range app.Roles {
				app.Roles[i].ApplicationID = app.ResourceID
			}
			if err := tx.Create(&app.Roles).Error; err != nil {
				return fmt.Errorf("failed to create application roles: %w", err)
			}
		}
		if len(app.Users) > 0 {
			var userRoles []model.ApplicationUserRole
			for _, user := range app.Users {
				var userRole model.ApplicationUserRole
				userRole.ApplicationID = app.ResourceID
				if len(user.Role) > 0 {
					for _, role := range app.Roles {
						if role.Name == user.Role {
							userRole.RoleID = role.ResourceID
							break
						}
					}
				}
				userRole.UserID = user.ResourceID
				userRoles = append(userRoles, userRole)
			}
			if err := tx.Create(&userRoles).Error; err != nil {
				return fmt.Errorf("failed to create application user roles: %w", err)
			}
			if addRequest != nil {
				// Create LDAP entry
				if err := ldapSession.Add(addRequest); err != nil {
					return fmt.Errorf("failed to create LDAP entry: %w", err)
				}
			}
		}

		return nil
	})
}

// UpdateApplication updates application information
func (s *ApplicationService) UpdateApplication(ctx context.Context, app *model.Application) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	// Update database record
	dbConn := db.Session(ctx)
	return dbConn.Transaction(func(tx *gorm.DB) error {
		if err := tx.Error; err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}

		var oriApp model.Application
		if err := tx.Where("resource_id = ?", app.ResourceID).First(&oriApp).Error; err != nil {
			return fmt.Errorf("failed to get original application: %w", err)
		}

		updateFields := []string{"name", "display_name", "display_name_i18n", "description", "description_i18n", "icon", "status", "grant_types", "uri", "redirect_uris", "scopes"}
		if err := tx.Where("resource_id = ?", app.ResourceID).Select(updateFields).Updates(app).Error; err != nil {
			return fmt.Errorf("failed to update application: %w", err)
		}
		return nil
	})
}

func (s *ApplicationService) UpdateApplicationEntry(ctx context.Context, appID string, entry []model.LDAPAttr) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	app, err := s.GetApplication(ctx, appID)
	if err != nil {
		return fmt.Errorf("failed to get application: %w", err)
	}
	entryAttrs := map[string][]string{}
	for _, attr := range entry {
		if attr.Name == "cn" {
			app.Name = attr.Value
		}
		if _, ok := entryAttrs[attr.Name]; !ok {
			entryAttrs[attr.Name] = []string{attr.Value}
		} else {
			entryAttrs[attr.Name] = append(entryAttrs[attr.Name], attr.Value)
		}
	}
	return db.Session(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Error; err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		modifyRequest := ldap.NewModifyRequest(app.LDAPDN, nil)
		for _, attr := range app.LDAPAttrs {
			if attr.UserAttr {
				if _, ok := entryAttrs[attr.Name]; !ok {
					modifyRequest.Delete(attr.Name, []string{attr.Value})
				} else {
					modifyRequest.Replace(attr.Name, entryAttrs[attr.Name])
				}
			}
		}
		if err := ldapSession.Modify(modifyRequest); err != nil {
			return fmt.Errorf("failed to modify LDAP entry: %w", err)
		}

		if err := tx.Model(&model.Application{}).Where("resource_id = ?", appID).Select("name").Updates(app).Error; err != nil {
			return fmt.Errorf("failed to update application: %w", err)
		}

		return nil
	})
}

// DeleteApplication deletes an application
func (s *ApplicationService) DeleteApplication(ctx context.Context, appID string) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	dbConn := db.Session(ctx)
	var app model.Application
	if err := dbConn.Unscoped().Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return fmt.Errorf("failed to find application: %w", err)
	}

	// Delete database record
	return dbConn.Transaction(func(tx *gorm.DB) error {
		if err := tx.Error; err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}

		if app.DeletedAt.Valid {
			// Delete related roles and authorizations
			if err := tx.Unscoped().Where("application_id = ?", appID).Delete(&model.ApplicationRole{}).Error; err != nil {
				return fmt.Errorf("failed to delete application roles: %w", err)
			}
			if err := tx.Unscoped().Where("application_id = ?", appID).Delete(&model.ApplicationUserRole{}).Error; err != nil {
				return fmt.Errorf("failed to delete application user roles: %w", err)
			}
			if err := tx.Unscoped().Delete(&app).Error; err != nil {
				return fmt.Errorf("failed to delete application: %w", err)
			}
		} else {
			// Delete related roles and authorizations
			if err := tx.Where("application_id = ?", appID).Delete(&model.ApplicationRole{}).Error; err != nil {
				return fmt.Errorf("failed to delete application roles: %w", err)
			}
			if err := tx.Where("application_id = ?", appID).Delete(&model.ApplicationUserRole{}).Error; err != nil {
				return fmt.Errorf("failed to delete application user roles: %w", err)
			}
			if err := tx.Delete(&app).Error; err != nil {
				return fmt.Errorf("failed to delete application: %w", err)
			}
		}
		if app.LDAPDN != "" {
			// Delete LDAP entry
			delRequest := ldap.NewDelRequest(app.LDAPDN, nil)
			if err := ldapSession.Del(delRequest); err != nil {
				if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
					return nil
				}
				return fmt.Errorf("failed to delete LDAP entry: %w", err)
			}
		}
		return nil
	})
}

// GetApplication retrieves application details
func (s *ApplicationService) GetApplication(ctx context.Context, appID string) (*model.Application, error) {

	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}
	if !settings.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}
	var app model.Application
	dbConn := db.Session(ctx)
	if err := dbConn.Unscoped().Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("failed to find application: %w", err)
	}
	// Get application roles
	if err := dbConn.Unscoped().Where("application_id = ?", appID).Find(&app.Roles).Error; err != nil {
		return nil, fmt.Errorf("failed to get application roles: %w", err)
	}
	if app.DeletedAt.Valid {
		app.Status = "deleted"
	}

	if app.LDAPDN == "" {
		return &app, nil
	}

	// Get application information from LDAP
	searchRequest := ldap.NewSearchRequest(
		app.LDAPDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		append([]string{"*"}, systemAttrs...),
		nil,
	)
	result, err := ldapSession.Search(searchRequest)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			app.LDAPDN = ""
			return &app, nil
		}
		return nil, fmt.Errorf("failed to search LDAP entries: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("application not found: %s", app.LDAPDN)
	}
	entry := result.Entries[0]
	for _, attr := range entry.Attributes {
		for _, value := range attr.Values {
			app.LDAPAttrs = append(app.LDAPAttrs, model.LDAPAttr{
				Name:     attr.Name,
				Value:    value,
				UserAttr: !slices.Contains(systemAttrs, attr.Name),
			})
		}
	}
	app.Name = entry.GetAttributeValue("cn")
	members := entry.GetAttributeValues("member")
	uniqueMembers := entry.GetAttributeValues("uniqueMember")
	members = append(members, uniqueMembers...)
	var dbUsers []model.User
	// Get application ldap users and roles
	err = dbConn.Model(&model.User{}).
		Select("t_user.*,t_application_role.name as role,t_application_user_role.role_id").
		Joins("LEFT JOIN t_application_user_role on t_user.resource_id = t_application_user_role.user_id and t_application_user_role.application_id = ? and t_application_user_role.deleted_at IS NULL", appID).
		Joins("LEFT JOIN t_application_role on t_application_role.resource_id = t_application_user_role.role_id and t_application_role.application_id = ? and t_application_role.deleted_at IS NULL", appID).
		Where("t_user.ldap_dn IN (?)", members).
		Find(&dbUsers).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get application users: %w", err)
	}

	for _, member := range members {
		user := w.Find(dbUsers, func(user model.User) bool {
			return user.LDAPDN == member
		})
		// Get user information from LDAP
		searchRequest := ldap.NewSearchRequest(
			member,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			append([]string{"*"}, systemAttrs...),
			nil,
		)
		result, err := ldapSession.Search(searchRequest)
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				user.Source = "local"
				app.Users = append(app.Users, user)
				continue
			}
			return nil, fmt.Errorf("failed to search LDAP entries: %w", err)
		}
		if len(result.Entries) == 0 {
			user.Source = "local"
			app.Users = append(app.Users, user)
			continue
		}
		entry = result.Entries[0]

		user.FullName = entry.GetAttributeValue(settings.DisplayNameAttr)
		user.Email = entry.GetAttributeValue(settings.EmailAttr)
		user.Username = entry.GetAttributeValue(settings.UserAttr)
		user.Base.CreatedAt = util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp"))
		user.Base.UpdatedAt = util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp"))
		user.LDAPDN = member
		user.Source = "ldap"
		if user.Status == "" {
			user.Status = "active"
		}
		app.Users = append(app.Users, user)
	}

	dbUsers = []model.User{}
	// Get application non ldap users
	err = dbConn.Model(&model.User{}).
		Select("t_user.*,t_application_role.name as role,t_application_user_role.role_id").
		Joins("JOIN t_application_user_role on t_user.resource_id = t_application_user_role.user_id  and t_application_user_role.`deleted_at` IS NULL").
		Joins("LEFT JOIN t_application_role on t_application_role.resource_id = t_application_user_role.role_id and t_application_role.`deleted_at` IS NULL").
		Where("t_user.ldap_dn NOT IN (?) and t_application_user_role.application_id = ?", members, appID).
		Find(&dbUsers).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get application users: %w", err)
	}
	for _, user := range dbUsers {
		if user.Source == "ldap" {
			user.Source = "local"
		}
		app.Users = append(app.Users, user)
	}

	return &app, nil
}

// ListApplications retrieves the application list
func (s *ApplicationService) ListApplications(ctx context.Context, keywords, status string, page, pageSize int) ([]model.Application, int64, error) {
	var apps []model.Application
	var total int64

	dbConn := db.Session(ctx)
	query := dbConn.Model(&model.Application{})
	if keywords != "" {
		query = query.Where("name LIKE ?", "%"+keywords+"%")
	}
	if status != "" {
		if status == "deleted" {
			query = query.Unscoped().Where("deleted_at IS NOT NULL")
		} else {
			query = query.Where("status = ?", status)
		}
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count applications: %w", err)
	}

	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&apps).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to find applications: %w", err)
	}

	ldapDNs := w.Filter(w.Map(apps, func(app model.Application) string {
		return app.LDAPDN
	}), func(ldapDN string) bool {
		return ldapDN != ""
	})
	apps = w.Map(apps, func(app model.Application) model.Application {
		if app.Status == "" {
			app.Status = "active"
		}
		return app
	})
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	// Get information from LDAP
	for _, ldapDN := range ldapDNs {
		searchRequest := ldap.NewSearchRequest(
			ldapDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			append([]string{"*"}, systemAttrs...),
			[]ldap.Control{},
		)
		result, err := ldapSession.Search(searchRequest)
		if err != nil {
			continue
		}
		if len(result.Entries) == 0 {
			continue
		}
		entry := result.Entries[0]
		for i, app := range apps {
			if app.LDAPDN == ldapDN {
				apps[i].Name = entry.GetAttributeValue("cn")
				apps[i].Base = consolemodel.Base{
					ID:         app.ID,
					ResourceID: app.ResourceID,
					CreatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp")),
					UpdatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp")),
				}
			}
		}
	}

	return apps, total, nil
}

// CreateApplicationRole creates an application role
func (s *ApplicationService) CreateApplicationRole(ctx context.Context, role *model.ApplicationRole) error {
	// Create application role
	conn := db.Session(ctx)
	if err := conn.Create(role).Error; err != nil {
		return fmt.Errorf("failed to create application role: %w", err)
	}
	return nil
}

func (s *ApplicationService) DeleteApplicationRole(ctx context.Context, appID, roleID string) error {
	conn := db.Session(ctx)
	if err := conn.Where("application_id = ? AND resource_id = ?", appID, roleID).Delete(&model.ApplicationRole{}).Error; err != nil {
		return fmt.Errorf("failed to delete application role: %w", err)
	}
	return nil
}

// AssignUserRole assigns a role to a user, writing the association to the database and adding the member info to the application's LDAP entry
func (s *ApplicationService) AssignUserRole(ctx context.Context, appID, userID, roleID string) error {
	logger := log.GetContextLogger(ctx)
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	applicationObjectClass, err := s.GetStringSetting(ctx, model.SettingLDAPApplicationObjectClass, "groupOfNames")
	if err != nil {
		return fmt.Errorf("failed to get LDAP application object class: %w", err)
	}

	conn := db.Session(ctx)
	// Get user information
	var user model.User
	if err := conn.Where("resource_id = ?", userID).First(&user).Error; err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	// Get application information
	var app model.Application
	if err := conn.Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return fmt.Errorf("failed to find application: %w", err)
	}
	// if roleID is not empty, check if the role exists
	if len(roleID) != 0 {
		// Get role information
		var role model.ApplicationRole
		if err := conn.Where("application_id = ? AND resource_id = ?", appID, roleID).First(&role).Error; err != nil {
			return fmt.Errorf("failed to find role: %w", err)
		}
	}
	// Get application info from LDAP, if member contains user.LDAPDN, do not modify LDAP entry
	modifyRequest := (*ldap.ModifyRequest)(nil)
	addRequest := (*ldap.AddRequest)(nil)

	baseDN, err := s.GetStringSetting(ctx, model.SettingLDAPApplicationBaseDN, "")
	if err != nil {
		return fmt.Errorf("failed to get LDAP application base DN: %w", err)
	}
	if len(baseDN) == 0 {
		return fmt.Errorf("LDAP application base DN is empty")
	}

	if app.LDAPDN == "" {
		app.LDAPDN = fmt.Sprintf("cn=%s,%s", app.Name, baseDN)
	}

	searchRequest := ldap.NewSearchRequest(
		app.LDAPDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"member", "objectClass", "uniqueMember"},
		nil,
	)

	result, err := ldapSession.Search(searchRequest)
	// If the application is not found, create it
	if (err != nil && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject)) || len(result.Entries) == 0 {
		level.Info(logger).Log("msg", "application not found, creating LDAP entry", "application", app.LDAPDN)
		addRequest = ldap.NewAddRequest(app.LDAPDN, nil)
		addRequest.Attribute("cn", []string{app.Name})
		addRequest.Attribute("objectClass", []string{"top", applicationObjectClass})
		userDNs := []string{user.LDAPDN}
		if applicationObjectClass == "groupOfUniqueNames" {
			addRequest.Attribute("uniqueMember", userDNs)
		} else {
			addRequest.Attribute("member", userDNs)
		}
	} else if err != nil {
		return fmt.Errorf("failed to search LDAP entry: %w", err)
	} else {
		modifyRequest = ldap.NewModifyRequest(app.LDAPDN, nil)
		entry := result.Entries[0]
		members := entry.GetAttributeValues("member")
		objectClass := entry.GetAttributeValues("objectClass")
		if slices.Contains(objectClass, "groupOfUniqueNames") {
			members = entry.GetAttributeValues("uniqueMember")
		}
		if !slices.ContainsFunc(objectClass, func(s string) bool {
			return s == "groupOfNames" || s == "groupOfUniqueNames"
		}) {
			modifyRequest.Add("objectClass", []string{applicationObjectClass})
		}
		if slices.Contains(members, user.LDAPDN) {
			modifyRequest = nil
		} else {
			if applicationObjectClass == "groupOfUniqueNames" {
				modifyRequest.Add("uniqueMember", []string{user.LDAPDN})
			} else {
				modifyRequest.Add("member", []string{user.LDAPDN})
			}
		}
	}

	return conn.Transaction(func(tx *gorm.DB) error {
		// Write to database
		userRole := model.ApplicationUserRole{
			ApplicationID: appID,
			UserID:        userID,
			RoleID:        roleID,
		}
		if err := tx.Create(&userRole).Error; err != nil {
			return fmt.Errorf("failed to create user role: %w", err)
		}

		if modifyRequest != nil {
			if err := ldapSession.Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to modify LDAP entry: %w", err)
			}
		}
		if addRequest != nil {
			tx.Model(&app).Update("ldap_dn", app.LDAPDN)
			if err := ldapSession.Add(addRequest); err != nil {
				var ldapError *ldap.Error
				if errors.As(err, &ldapError) {
					switch ldapError.ResultCode {
					case ldap.LDAPResultEntryAlreadyExists:
						return util.NewError("E50040", "Application already exists in LDAP")
					case ldap.LDAPResultNoSuchObject:
						level.Info(logger).Log("msg", "baseDN may not exist, creating organizational unit", "dn", baseDN)
						if err := s.RecursiveCreateOrganizationalUnitEntry(ctx, baseDN); err != nil {
							return fmt.Errorf("failed to create LDAP entry: %w", err)
						}
						level.Info(logger).Log("msg", "baseDN(organizational unit) created", "dn", baseDN)
						if err := ldapSession.Add(addRequest); err != nil {
							return fmt.Errorf("failed to create LDAP entry: %w", err)
						}
						return nil
					default:
						return fmt.Errorf("failed to create LDAP entry: %w", err)
					}
				}
				return fmt.Errorf("failed to add LDAP entry: %w", err)
			}
		}

		return nil
	})
}

// UnassignUserRole unassigns a role from a user, removes the association from the database, and deletes the member info from the application's LDAP entry
func (s *ApplicationService) UnassignUserRole(ctx context.Context, appID, userID string) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	conn := db.Session(ctx)
	// Get user information
	var user model.User
	if err := conn.Where("resource_id = ?", userID).First(&user).Error; err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	// Get application information
	var app model.Application
	if err := conn.Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return fmt.Errorf("failed to find application: %w", err)
	}

	// Get application info from LDAP, if after removing this member there are no other members, remove groupOfNames from the application
	searchRequest := ldap.NewSearchRequest(
		app.LDAPDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"member", "uniqueMember"},
		nil,
	)
	modifyRequest := (*ldap.ModifyRequest)(nil)
	deleteRequest := (*ldap.DelRequest)(nil)
	result, err := ldapSession.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search LDAP entries: %w", err)
	}
	if len(result.Entries) == 0 {
		return fmt.Errorf("application not found: %s", app.LDAPDN)
	}
	entry := result.Entries[0]

	if members := entry.GetAttributeValues("member"); slices.Contains(members, user.LDAPDN) {
		modifyRequest = ldap.NewModifyRequest(app.LDAPDN, nil)
		modifyRequest.Delete("member", []string{user.LDAPDN})
		// If there are no other members, remove groupOfNames
		if len(members) == 1 && members[0] == user.LDAPDN {
			deleteRequest = ldap.NewDelRequest(app.LDAPDN, nil)
			modifyRequest = nil
		}
	} else if members := entry.GetAttributeValues("uniqueMember"); slices.Contains(members, user.LDAPDN) {
		modifyRequest = ldap.NewModifyRequest(app.LDAPDN, nil)
		modifyRequest.Delete("uniqueMember", []string{user.LDAPDN})
		// If there are no other members, remove groupOfNames
		if len(members) == 1 && members[0] == user.LDAPDN {
			deleteRequest = ldap.NewDelRequest(app.LDAPDN, nil)
			modifyRequest = nil
		}
	} else {
		modifyRequest = nil
	}

	return conn.Transaction(func(tx *gorm.DB) error {
		// Remove association from database
		if err := tx.Where("application_id = ? AND user_id = ?", appID, userID).Unscoped().Delete(&model.ApplicationUserRole{}).Error; err != nil {
			return fmt.Errorf("failed to delete user role: %w", err)
		}
		if modifyRequest != nil {
			if err := ldapSession.Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to modify LDAP entry: %w", err)
			}
		}
		if deleteRequest != nil {
			if err := tx.Model(&app).Update("ldap_dn", "").Error; err != nil {
				return fmt.Errorf("failed to update application LDAP DN: %w", err)
			}
			if err := ldapSession.Del(deleteRequest); err != nil {
				return fmt.Errorf("failed to delete LDAP entry: %w", err)
			}
		}
		return nil
	})
}

// ListApplicationRoles retrieves the list of application roles
func (s *ApplicationService) ListApplicationRoles(ctx context.Context, appID string) ([]model.ApplicationRole, error) {
	var roles []model.ApplicationRole
	if err := db.Session(ctx).Where("application_id = ?", appID).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("failed to find application roles: %w", err)
	}
	return roles, nil
}

// ListApplicationUsers retrieves the list of users for an application
func (s *ApplicationService) ListApplicationUsers(ctx context.Context, appID string) ([]model.User, error) {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP settings: %w", err)
	}
	if !settings.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}
	dbConn := db.Session(ctx)
	var app model.Application
	if err := dbConn.Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("failed to find application: %w", err)
	}
	// Get application information from LDAP
	searchRequest := ldap.NewSearchRequest(
		app.LDAPDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)
	result, err := ldapSession.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP entries: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("application not found: %s", app.LDAPDN)
	}
	entry := result.Entries[0]
	app.Name = entry.GetAttributeValue("cn")
	members := entry.GetAttributeValues("member")
	uniqueMembers := entry.GetAttributeValues("uniqueMember")
	members = append(members, uniqueMembers...)

	var dbUsers []model.User
	// Get application users
	dbConn.Model(&model.User{}).
		Select("t_user.*,t_application_role.name as role,t_application_user_role.role_id").
		Joins("LEFT JOIN t_application_user_role on t_user.resource_id = t_application_user_role.user_id and t_application_user_role.application_id = ?", appID).
		Joins("LEFT JOIN t_application_role on t_application_role.resource_id = t_application_user_role.role_id and t_application_role.application_id = ?", appID).
		Where("t_user.ldap_dn IN (?)", members).
		Find(&dbUsers)

	for _, member := range members {
		// Get user information from LDAP
		searchRequest := ldap.NewSearchRequest(
			member,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			append([]string{"*"}, systemAttrs...),
			nil,
		)
		result, err := ldapSession.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to search LDAP entries: %w", err)
		}
		if len(result.Entries) == 0 {
			continue
		}
		entry = result.Entries[0]
		user := w.Find(dbUsers, func(user model.User) bool {
			return user.LDAPDN == member
		})
		user.FullName = entry.GetAttributeValue(settings.DisplayNameAttr)
		user.Email = entry.GetAttributeValue(settings.EmailAttr)
		user.Username = entry.GetAttributeValue(settings.UserAttr)
		user.Base.CreatedAt = util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp"))
		user.Base.UpdatedAt = util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp"))
		user.LDAPDN = member
		user.Source = "ldap"
		app.Users = append(app.Users, user)
	}

	return dbUsers, nil
}

// ImportLDAPApplications imports LDAP applications
func (s *ApplicationService) ImportLDAPApplications(ctx context.Context, applicationDNs []string) ([]model.Application, error) {
	logger := log.GetContextLogger(ctx)
	applicationBaseDN, err := s.GetStringSetting(ctx, model.SettingLDAPApplicationBaseDN, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP application base DN: %w", err)
	}
	if len(applicationBaseDN) == 0 {
		return nil, fmt.Errorf("LDAP application base DN is empty")
	}

	applicationFilter, err := s.GetStringSetting(ctx, model.SettingLDAPApplicationFilter, "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))")
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP application filter: %w", err)
	}
	if applicationFilter == "" {
		applicationFilter = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
	}

	if len(applicationDNs) == 0 {
		attributes := []string{"cn", "entryUUID", "createTimestamp", "modifyTimestamp"}
		entries, err := s.FilterLDAPEntries(ctx, applicationBaseDN, applicationFilter, attributes)
		if err != nil {
			if strings.Contains(err.Error(), "No Such Object") {
				return []model.Application{}, nil
			}
			return nil, fmt.Errorf("failed to filter LDAP entries: %w", err)
		}
		var applications []model.Application
		conn := db.Session(ctx)
		// Batch match application information from database by ldapDN, 20 at a time
		for i := 0; i < len(entries); i += 20 {
			var existingApplications []model.Application
			batch := entries[i:min(i+20, len(entries))]
			applicationDNs := w.Map(batch, func(entry *ldap.Entry) string {
				return entry.DN
			})
			if err := conn.Where("ldap_dn IN (?)", applicationDNs).Find(&existingApplications).Error; err != nil {
				return nil, fmt.Errorf("failed to find applications: %w", err)
			}
			for _, entry := range batch {
				application := w.Find(existingApplications, func(application model.Application) bool {
					return application.LDAPDN == entry.DN
				})
				if application.ResourceID != "" {
					// If already exists, skip
					continue
				}
				var existingApplication model.Application
				if err := conn.Where("name = ?", entry.GetAttributeValue("cn")).First(&existingApplication).Error; err != nil {
					if err != gorm.ErrRecordNotFound {
						return nil, fmt.Errorf("failed to check existing application: %w", err)
					}
				} else if existingApplication.ResourceID != "" {
					// If application name matches, mark as bindable (return ID field)
					applications = append(applications, model.Application{
						Name:   entry.GetAttributeValue("cn"),
						LDAPDN: entry.DN,
						Base: consolemodel.Base{
							ResourceID: entry.GetAttributeValue("entryUUID"),
							CreatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp")),
							UpdatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp")),
						},
					})
					continue
				}
				applications = append(applications, model.Application{
					Name:   entry.GetAttributeValue("cn"),
					LDAPDN: entry.DN,
				})
			}
		}
		return applications, nil
	}
	ldapClient, err := s.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to get LDAP client: %v", err)
	}

	defer ldapClient.Close()

	applications := []model.Application{}
	err = db.Session(ctx).Transaction(func(tx *gorm.DB) error {
		for _, applicationDN := range applicationDNs {
			searchReq := ldap.NewSearchRequest(
				applicationDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
				"(objectClass=*)",
				[]string{"entryUUID", "createTimestamp", "modifyTimestamp", "member", "uniqueMember", "cn"},
				nil,
			)
			result, err := ldapClient.Search(searchReq)
			if err != nil {
				return fmt.Errorf("Failed to search LDAP user: %v", err)
			}
			if len(result.Entries) == 0 {
				return fmt.Errorf("Application not found: %s", applicationDN)
			}
			entry := result.Entries[0]
			application := model.Application{
				Name:   entry.GetAttributeValue("cn"),
				LDAPDN: entry.DN,
				Base: consolemodel.Base{
					ResourceID: entry.GetAttributeValue("entryUUID"),
					CreatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp")),
					UpdatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp")),
				},
			}
			var existingApplication model.Application
			if err := tx.Where("ldap_dn = ?", entry.DN).First(&existingApplication).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					return fmt.Errorf("Failed to check existing application: %v", err)
				}
			} else if existingApplication.ResourceID != "" {
				// If already exists, return error
				return fmt.Errorf("Application already exists: %s", application.Name)
			}
			if err := tx.Where("name = ?", entry.GetAttributeValue("cn")).Order("name").First(&existingApplication).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					level.Error(logger).Log("msg", "Failed to check existing application", "err", err.Error())
					return fmt.Errorf("failed to check existing application: %w", err)
				}
			}
			memberDNs := entry.GetAttributeValues("member")
			uniqueMemberDNs := entry.GetAttributeValues("uniqueMember")
			memberDNs = append(memberDNs, uniqueMemberDNs...)
			if existingApplication.ResourceID != "" {
				// If username or email matches, bind
				existingApplication.LDAPDN = application.LDAPDN
				if err := tx.Select("LDAPDN").Updates(&existingApplication).Error; err != nil {
					return fmt.Errorf("failed to update application: %w", err)
				}
				if len(memberDNs) > 0 {
					var users []model.User
					if err := tx.Model(&model.User{}).Select("t_user.id", "t_user.resource_id").Where("ldap_dn IN (?)", memberDNs).
						Joins("LEFT JOIN t_application_user_role as aur ON t_user.resource_id = aur.user_id AND aur.application_id = ?", existingApplication.ResourceID).
						Where("aur.user_id IS NULL").
						Find(&users).Error; err != nil {
						return fmt.Errorf("failed to get users: %w", err)
					}
					for _, user := range users {
						tx.Create(&model.ApplicationUserRole{ApplicationID: existingApplication.ResourceID, UserID: user.ResourceID})
					}
				}
			} else {
				if err := tx.Create(&application).Error; err != nil {
					return fmt.Errorf("Failed to create application: %v", err)
				}
				if len(memberDNs) > 0 {
					var users []model.User
					if err := tx.Model(&model.User{}).Select("id", "resource_id").Where("ldap_dn IN (?)", memberDNs).Find(&users).Error; err != nil {
						return fmt.Errorf("failed to get users: %w", err)
					}
					for _, user := range users {
						tx.Create(&model.ApplicationUserRole{ApplicationID: application.ResourceID, UserID: user.ResourceID})
					}
				}
			}
			applications = append(applications, application)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return applications, nil

}

// CreateApplicationKey creates a new key for an application.
func (s *ApplicationService) CreateApplicationKey(ctx context.Context, appID, name string, expiresAt *time.Time) (*model.ApplicationKey, error) {
	conn := db.Session(ctx)
	var app model.Application
	if err := conn.Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("failed to find application: %w", err)
	}
	var count int64
	if err := conn.Model(&model.ApplicationKey{}).Where("application_id = ?", appID).Count(&count).Error; err != nil {
		return nil, fmt.Errorf("failed to count application keys: %w", err)
	}
	if count >= 10 {
		return nil, fmt.Errorf("application key count limit reached")
	}

	// Generate access key ID and secret
	clientId := fmt.Sprintf("APP-%s", util.GenerateRandomString(20))
	clientSecret := util.GenerateRandomString(40)

	key := model.ApplicationKey{
		ApplicationID: app.ResourceID,
		ClientID:      clientId,
		ClientSecret:  *safe.NewEncryptedString(clientSecret, os.Getenv(safe.SecretEnvName)),
		ExpiresAt:     expiresAt,
		Name:          name,
	}
	if err := conn.Create(&key).Error; err != nil {
		return nil, fmt.Errorf("failed to create application key: %w", err)
	}
	return &key, nil
}

// DeleteApplicationKey deletes a key for an application.
func (s *ApplicationService) DeleteApplicationKey(ctx context.Context, appID string, keyID string) error {
	conn := db.Session(ctx)
	var key model.ApplicationKey
	if err := conn.Where("application_id = ? and resource_id = ?", appID, keyID).First(&key).Error; err != nil {
		return fmt.Errorf("failed to find application key: %w", err)
	}
	if err := conn.Delete(&key).Error; err != nil {
		return fmt.Errorf("failed to delete application key: %w", err)
	}
	return nil
}

// ListApplicationKeys lists all keys for an application.
func (s *ApplicationService) ListApplicationKeys(ctx context.Context, appID string) ([]model.ApplicationKey, error) {
	conn := db.Session(ctx)
	var keys []model.ApplicationKey
	if err := conn.Where("application_id = ?", appID).Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to list application keys: %w", err)
	}
	return keys, nil
}

// CreateApplicationIssuerKey creates a new issuer key for an application.
func (s *ApplicationService) CreateApplicationIssuerKey(ctx context.Context, appID, name, algorithm, privateKey string) (*model.ApplicationPrivateKey, error) {
	conn := db.Session(ctx)
	// Check if application exists and key count
	var app model.Application
	if err := conn.Model(&model.Application{}).Where("resource_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("failed to find application: %w", err)
	}
	var count int64
	if err := conn.Model(&model.ApplicationPrivateKey{}).Where("application_id = ?", appID).Count(&count).Error; err != nil {
		return nil, fmt.Errorf("failed to count application private keys: %w", err)
	}
	if count >= 10 {
		return nil, fmt.Errorf("application private key count limit reached")
	}
	if privateKey == "" {
		pk, err := jwtutil.NewRandomKey(algorithm)
		if err != nil {
			return nil, util.NewError("E40155", "failed to generate random key", err)
		}
		privateKey = string(pk)
	} else {
		pk, err := model.ParsePrivateKey(privateKey, algorithm)
		if err != nil {
			return nil, util.NewError("E40154", "invalid private key", err)
		}
		switch k := pk.(type) {
		case *rsa.PrivateKey:
			size, err := strconv.Atoi(strings.TrimPrefix(algorithm, "RS"))
			if err != nil {
				return nil, fmt.Errorf("invalid algorithm %s for RSA", algorithm)
			}
			if k.Size() != size {
				return nil, fmt.Errorf("invalid RSA key size: %d", k.Size())
			}
		case *ecdsa.PrivateKey:
			size, err := strconv.Atoi(strings.TrimPrefix(algorithm, "ES"))
			if err != nil {
				return nil, fmt.Errorf("invalid algorithm %s for ECDSA", algorithm)
			}
			if k.Curve.Params().BitSize != size {
				return nil, fmt.Errorf("invalid ECDSA key size: %d", k.Curve.Params().BitSize)
			}
		case []byte:
		default:
			return nil, fmt.Errorf("invalid private key type: %T", pk)
		}
	}

	key := model.ApplicationPrivateKey{
		ApplicationID: app.ResourceID,
		Name:          name,
		Algorithm:     algorithm,
		PrivateKey:    *safe.NewEncryptedString(privateKey, os.Getenv(safe.SecretEnvName)),
	}
	if err := conn.Create(&key).Error; err != nil {
		return nil, fmt.Errorf("failed to create application issuer key: %w", err)
	}
	return &key, nil
}

// DeleteApplicationIssuerKey deletes an issuer key for an application.
func (s *ApplicationService) DeleteApplicationIssuerKey(ctx context.Context, appID, keyID string) error {
	conn := db.Session(ctx)
	var key model.ApplicationPrivateKey
	if err := conn.Where("application_id = ? and resource_id = ?", appID, keyID).First(&key).Error; err != nil {
		return fmt.Errorf("failed to find application issuer key: %w", err)
	}
	if err := conn.Delete(&key).Error; err != nil {
		return fmt.Errorf("failed to delete application issuer key: %w", err)
	}
	return nil
}

// ListApplicationIssuerKeys lists all issuer keys for an application.
func (s *ApplicationService) ListApplicationIssuerKeys(ctx context.Context, appID string) ([]model.ApplicationPrivateKey, error) {
	conn := db.Session(ctx)
	var keys []model.ApplicationPrivateKey
	if err := conn.Where("application_id = ?", appID).Limit(20).Order("id DESC").Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to list application issuer keys: %w", err)
	}
	return keys, nil
}
