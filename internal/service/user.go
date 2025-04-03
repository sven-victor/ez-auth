package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	"github.com/gofrs/uuid"
	"github.com/sven-victor/ez-auth/internal/model"
	"github.com/sven-victor/ez-console/pkg/db"
	"github.com/sven-victor/ez-console/pkg/middleware"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-console/pkg/util"
	"github.com/sven-victor/ez-console/server"
	"github.com/sven-victor/ez-utils/log"
	w "github.com/sven-victor/ez-utils/wrapper"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"

	"gorm.io/gorm"
)

type UserService struct {
	server.Service
}

func NewUserService(svc server.Service) *UserService {
	return &UserService{
		Service: svc,
	}
}

func hash(password []byte) (string, error) {
	c := sha256_crypt.New()
	salt := base64.StdEncoding.EncodeToString(w.M(uuid.NewV4()).Bytes())
	return c.Generate(password, []byte("$5$"+salt))
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, user *consolemodel.User, roleIDs []string, ldapAttrs []model.LDAPAttr) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP settings: %w", err)
	}

	user.LDAPDN = fmt.Sprintf("%s=%s,%s", settings.UserAttr, user.Username, settings.BaseDN)
	addRequest := ldap.NewAddRequest(user.LDAPDN, nil)
	if len(ldapAttrs) > 0 {
		entryAttrs := map[string][]string{}
		for _, attr := range ldapAttrs {
			switch attr.Name {
			case settings.UserAttr:
				user.Username = attr.Value
			case settings.DisplayNameAttr:
				user.FullName = attr.Value
			case settings.EmailAttr:
				user.Email = attr.Value
			}
			if _, ok := entryAttrs[attr.Name]; !ok {
				entryAttrs[attr.Name] = []string{attr.Value}
			} else {
				entryAttrs[attr.Name] = append(entryAttrs[attr.Name], attr.Value)
			}
		}
		for name, values := range entryAttrs {
			addRequest.Attribute(name, values)
		}
		addRequest.DN = fmt.Sprintf("%s=%s,%s", settings.UserAttr, user.Username, settings.BaseDN)
		user.LDAPDN = addRequest.DN
	} else {
		var attrs map[string][]string = map[string][]string{
			"cn":                     {user.Username},
			"sn":                     {user.FullName},
			"objectClass":            {"top", "organizationalPerson", "inetOrgPerson"},
			settings.UserAttr:        {user.Username},
			settings.DisplayNameAttr: {user.FullName},
			settings.EmailAttr:       {user.Email},
		}
		for name, values := range attrs {
			addRequest.Attribute(name, values)
		}
		if len(user.Password) > 0 {
			hashedPassword, err := hash([]byte(user.Password))
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}
			addRequest.Attribute("userPassword", []string{"{CRYPT}" + hashedPassword})
			user.Status = consolemodel.UserStatusPasswordExpired
		}
	}
	return db.Session(ctx).Transaction(func(tx *gorm.DB) error {
		user.Password = ""
		// Create database record
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
		// Assign roles
		if len(roleIDs) > 0 {
			if err := tx.Where("resource_id IN ?", roleIDs).Find(&user.Roles).Error; err != nil {
				return fmt.Errorf("update user roles failed: %w", err)
			}
			if err := tx.Model(&user).Association("Roles").Append(user.Roles); err != nil {
				return fmt.Errorf("assign roles to user failed: %w", err)
			}
		}
		if err := ldapSession.Add(addRequest); err != nil {
			return fmt.Errorf("failed to create LDAP entry: %w", err)
		}
		return nil
	})
}

// UpdateUser updates user information
func (s *UserService) UpdateUserEntry(ctx context.Context, id string, entry []model.LDAPAttr) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	user, err := s.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP settings: %w", err)
	}
	entryAttrs := map[string][]string{}
	for _, attr := range entry {
		switch attr.Name {
		case settings.UserAttr:
			user.Username = attr.Value
		case settings.DisplayNameAttr:
			user.FullName = attr.Value
		case settings.EmailAttr:
			user.Email = attr.Value
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

		modifyRequest := ldap.NewModifyRequest(user.LDAPDN, nil)
		for _, attr := range user.LDAPAttrs {
			if attr.UserAttr {
				if _, ok := entryAttrs[attr.Name]; !ok {
					modifyRequest.Delete(attr.Name, []string{attr.Value})
				} else {
					modifyRequest.Replace(attr.Name, entryAttrs[attr.Name])
				}
			}
		}
		if err := ldapSession.Modify(modifyRequest); err != nil {
			return fmt.Errorf("failed to update LDAP entry: %w", err)
		}
		if err := tx.Model(&model.User{}).Where("resource_id = ?", id).Select("username", "full_name", "email").Updates(user).Error; err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
		middleware.DeleteUserCache(user.ResourceID)
		return nil
	})
}

type UpdateUserRequest struct {
	Email       string   `json:"email"`
	FullName    string   `json:"full_name"`
	Status      string   `json:"status"`
	MFAEnforced bool     `json:"mfa_enforced"`
	Source      string   `json:"source"`
	LDAPDN      string   `json:"ldap_dn"`
	Phone       string   `json:"phone"`
	Avatar      string   `json:"avatar"`
	RoleIDs     []string `json:"role_ids"`
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(ctx context.Context, userID string, req UpdateUserRequest) error {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to get LDAP settings: %w", err)
	}

	// Update database record
	return db.Session(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Error; err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		updates := map[string]any{
			"email":        req.Email,
			"full_name":    req.FullName,
			"mfa_enforced": req.MFAEnforced,
		}
		if req.Source == string(consolemodel.UserSourceLocal) {
			updates["source"] = req.Source
			updates["ldap_dn"] = ""
		} else if req.LDAPDN != "" {
			updates["ldap_dn"] = req.LDAPDN
			user.LDAPDN = req.LDAPDN
		}
		if req.Status == consolemodel.UserStatusActive || req.Status == consolemodel.UserStatusDisabled {
			updates["status"] = req.Status
		}
		if req.Phone != "" {
			updates["phone"] = req.Phone
		}
		if req.Avatar != "" {
			updates["avatar"] = req.Avatar
		}
		if err := tx.Model(&model.User{}).Where("resource_id = ?", userID).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
		if len(req.RoleIDs) > 0 {
			if err := tx.Where("resource_id IN ?", req.RoleIDs).Find(&user.Roles).Error; err != nil {
				return fmt.Errorf("update user roles failed: %w", err)
			}
			if err := tx.Model(&user).Association("Roles").Replace(user.Roles); err != nil {
				return fmt.Errorf("assign roles to user failed: %w", err)
			}
		} else {
			if err := tx.Model(&user).Association("Roles").Clear(); err != nil {
				return fmt.Errorf("clear user roles failed: %w", err)
			}
		}
		if req.Source == string(consolemodel.UserSourceLDAP) && user.LDAPDN != "" {
			// Update LDAP entry
			modifyRequest := ldap.NewModifyRequest(user.LDAPDN, nil)
			modifyRequest.Replace(settings.DisplayNameAttr, []string{req.FullName})
			modifyRequest.Replace(settings.EmailAttr, []string{req.Email})
			if err := ldapSession.Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to update LDAP entry: %w", err)
			}
		}
		middleware.DeleteUserCache(user.ResourceID)
		return nil
	})
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	dbConn := db.Session(ctx)

	var user consolemodel.User
	if err := dbConn.Unscoped().Where("resource_id = ?", userID).First(&user).Error; err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Delete database record
	return dbConn.Transaction(func(tx *gorm.DB) error {
		if err := tx.Error; err != nil {
			return fmt.Errorf("failed to start transaction: %w", err)
		}

		if user.DeletedAt.Valid {
			return tx.Unscoped().Select("Roles").Delete(&user).Error
		}
		if err := tx.Delete(&user).Error; err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}
		ldapSession, err := s.Service.GetLDAPSession(ctx)
		if err != nil {
			return fmt.Errorf("failed to get LDAP session: %w", err)
		}
		defer ldapSession.Close()
		// Delete LDAP entry
		delRequest := ldap.NewDelRequest(user.LDAPDN, nil)
		if err := ldapSession.Del(delRequest); err != nil {
			return fmt.Errorf("failed to delete LDAP entry: %w", err)
		}
		middleware.DeleteUserCache(user.ResourceID)
		return nil
	})
}

var systemAttrs = []string{"entryUUID", "createTimestamp", "modifyTimestamp", "memberOf"}

type GetUserOptions struct {
	WithSoftDeleted bool
	WithRoles       bool
}

func WithSoftDeleted(withSoftDeleted bool) func(*GetUserOptions) {
	return func(opts *GetUserOptions) {
		opts.WithSoftDeleted = withSoftDeleted
	}
}

func WithRoles(withRoles bool) func(*GetUserOptions) {
	return func(opts *GetUserOptions) {
		opts.WithRoles = withRoles
	}
}

// GetUser retrieves user details
func (s *UserService) GetUser(ctx context.Context, userID string, opts ...func(*GetUserOptions)) (*model.User, error) {
	var options GetUserOptions
	for _, opt := range opts {
		opt(&options)
	}

	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP settings: %w", err)
	}
	if !settings.Enabled {
		return nil, util.ErrorResponse{
			Code: "E50099",
			Err:  fmt.Errorf("LDAP is not enabled"),
		}
	}

	// Get user information from database
	dbConn := db.Session(ctx)
	var user model.User
	query := dbConn.Model(&model.User{})
	if options.WithSoftDeleted {
		query = query.Unscoped()
	}
	if options.WithRoles {
		query = query.Preload("Roles")
	}
	if err := query.Where("resource_id = ?", userID).First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if user.LDAPDN == "" {
		return &user, nil
	}

	logger := log.GetContextLogger(ctx)

	// Match users obtained from LDAP
	attributes := append([]string{"*"}, systemAttrs...)
	searchRequest := ldap.NewSearchRequest(
		user.LDAPDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		attributes,
		nil,
	)

	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()
	level.Info(logger).Log("msg", "Searching LDAP entries", "filter", searchRequest.Filter)
	result, err := ldapSession.Search(searchRequest)
	if err != nil || len(result.Entries) == 0 {
		user.Status = model.UserStatusInvalidLDAPBinding
		return &user, nil
	} else if len(result.Entries) > 1 {
		return nil, fmt.Errorf("multiple users found")
	}
	level.Info(logger).Log("msg", "LDAP entries found", "count", len(result.Entries))

	entry := result.Entries[0]

	if user.LDAPDN != entry.DN {
		return nil, fmt.Errorf("user not found")
	}

	user.Username = entry.GetAttributeValue(settings.UserAttr)
	user.Email = entry.GetAttributeValue(settings.EmailAttr)
	user.FullName = entry.GetAttributeValue(settings.DisplayNameAttr)
	user.Base.CreatedAt = util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp"))
	user.Base.UpdatedAt = util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp"))

	for _, attr := range entry.Attributes {
		if len(attr.Values) == 0 {
			user.LDAPAttrs = append(user.LDAPAttrs, model.LDAPAttr{
				Name:     attr.Name,
				Value:    entry.GetAttributeValue(attr.Name),
				UserAttr: !slices.Contains(systemAttrs, attr.Name),
			})
		} else {
			for _, value := range attr.Values {
				user.LDAPAttrs = append(user.LDAPAttrs, model.LDAPAttr{
					Name:     attr.Name,
					Value:    string(value),
					UserAttr: !slices.Contains(systemAttrs, attr.Name),
				})
			}
		}

	}
	return &user, nil
}

// ListUsers retrieves the user list
func (s *UserService) ListUsers(ctx context.Context, keywords, status string, current int, pageSize int, source string) ([]model.User, int64, error) {
	passwordExpiryDays, err := s.Service.GetIntSetting(ctx, consolemodel.SettingPasswordExpiryDays, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get password expiry days: %w", err)
	}
	var users []model.User
	var total int64
	query := db.Session(ctx).Model(&model.User{}).Preload("Roles")
	switch source {
	case "ldap":
		query = query.Where("ldap_dn IS NOT NULL and ldap_dn != '' or source = ?", consolemodel.UserSourceLDAP)
	case "all", "":
	default:
		query = query.Where("source = ?", source)
	}
	if keywords != "" {
		query = query.Where("username LIKE ? OR email LIKE ?", "%"+keywords+"%", "%"+keywords+"%")
	}
	switch status {
	case consolemodel.UserStatusDeleted:
		query = query.Unscoped().Where("deleted_at IS NOT NULL")
	case consolemodel.UserStatusLocked:
		query = query.Where("locked_until > ?", time.Now())
	case consolemodel.UserStatusPasswordExpired:
		if passwordExpiryDays > 0 {
			query = query.Where("password_changed_at < ? or password_changed_at is NULL or status = ?", time.Now().Add(-time.Duration(passwordExpiryDays)*24*time.Hour), consolemodel.UserStatusPasswordExpired)
		} else {
			query = query.Where("status = ?", consolemodel.UserStatusPasswordExpired)
		}
	case consolemodel.UserStatusActive, consolemodel.UserStatusDisabled:
		query = query.Where("status = ?", status)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Pagination query
	offset := (current - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		return nil, 0, err
	}

	ldapDNs := w.Filter(w.Map(users, func(user model.User) string {
		return user.LDAPDN
	}), func(ldapDN string) bool {
		return ldapDN != ""
	})

	users = w.Map(users, func(u model.User) model.User {
		if u.IsDeleted() {
			u.Status = consolemodel.UserStatusDeleted
		} else if u.IsLocked() {
			u.Status = consolemodel.UserStatusLocked
		} else if u.Source == consolemodel.UserSourceLDAP && u.LDAPDN == "" {
			u.Status = model.UserStatusInvalidLDAPBinding
		} else if u.IsPasswordExpired(passwordExpiryDays) {
			u.Status = consolemodel.UserStatusPasswordExpired
		}
		return u
	})
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get LDAP settings: %w", err)
	}

	// Get information from LDAP
	for _, ldapDN := range ldapDNs {
		searchRequest := ldap.NewSearchRequest(
			ldapDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			append([]string{"*"}, systemAttrs...),
			[]ldap.Control{},
		)
		var entry *ldap.Entry
		var err error
		result, err := ldapSession.Search(searchRequest)
		if err == nil && len(result.Entries) > 0 {
			entry = result.Entries[0]
		}
		for i, user := range users {
			if user.LDAPDN == ldapDN {
				if entry == nil {
					if user.Status == consolemodel.UserStatusActive {
						users[i].Status = model.UserStatusInvalidLDAPBinding
					}
				} else {
					users[i].Email = entry.GetAttributeValue(settings.EmailAttr)
					users[i].FullName = entry.GetAttributeValue(settings.DisplayNameAttr)
					users[i].Username = entry.GetAttributeValue(settings.UserAttr)
					users[i].Source = consolemodel.UserSourceLDAP
					users[i].Base = consolemodel.Base{
						ID:         user.ID,
						ResourceID: user.ResourceID,
						CreatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp")),
						UpdatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp")),
					}
					users[i].Source = consolemodel.UserSourceLDAP
				}
			}
		}
	}
	return users, total, nil

}

// UpdateLastLoginTime updates the last login time
func (s *UserService) UpdateLastLoginTime(ctx context.Context, userID string) error {
	dbConn := db.Session(ctx)
	return dbConn.Model(&consolemodel.User{}).Where("resource_id = ?", userID).Update("last_login_at", time.Now().Unix()).Error
}

// ImportLDAPUsers imports LDAP users
func (s *UserService) ImportLDAPUsers(ctx context.Context, userDNs []string) ([]model.User, error) {
	logger := log.GetContextLogger(ctx)
	settings, err := s.GetLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP settings: %w", err)
	}
	if len(userDNs) == 0 {
		filter := fmt.Sprintf("(&(|(%s=%s)(%s=%s))%s)", settings.UserAttr, "*", settings.EmailAttr, "*", settings.UserFilter)
		attributes := []string{settings.UserAttr, settings.EmailAttr, settings.DisplayNameAttr, "entryUUID", "createTimestamp", "modifyTimestamp"}
		entries, err := s.FilterLDAPEntries(ctx, settings.BaseDN, filter, attributes)
		if err != nil {
			return nil, fmt.Errorf("failed to filter LDAP entries: %w", err)
		}
		var users []model.User
		conn := db.Session(ctx)
		// Batch match user information from database by ldapDN, 20 at a time
		for i := 0; i < len(entries); i += 20 {
			var existingUsers []model.User
			batch := entries[i:min(i+20, len(entries))]
			userDNs := w.Map(batch, func(entry *ldap.Entry) string {
				return entry.DN
			})
			err := conn.Model(&model.User{}).Where("ldap_dn IN (?)", userDNs).Find(&existingUsers).Error
			if err != nil {
				return nil, fmt.Errorf("failed to get users: %w", err)
			}
			for _, entry := range batch {
				user := w.Find(existingUsers, func(user model.User) bool {
					return user.LDAPDN == entry.DN
				})
				if user.ResourceID != "" {
					// If already exists, skip
					continue
				}
				var existingUser model.User
				if err := conn.Where("username = ? or email = ?", entry.GetAttributeValue(settings.UserAttr), entry.GetAttributeValue(settings.EmailAttr)).Order("username").First(&existingUser).Error; err != nil {
					if err != gorm.ErrRecordNotFound {
						level.Error(logger).Log("msg", "Failed to check existing user", "err", err.Error())
						return nil, fmt.Errorf("failed to check existing user: %w", err)
					}
				} else if existingUser.ResourceID != "" {
					// If username or email matches, mark as bindable (return ID field)
					users = append(users, model.User{
						LDAPDN:   entry.DN,
						Status:   "active",
						Username: entry.GetAttributeValue(settings.UserAttr),
						Email:    entry.GetAttributeValue(settings.EmailAttr),
						FullName: entry.GetAttributeValue(settings.DisplayNameAttr),
						Base: consolemodel.Base{
							ResourceID: entry.GetAttributeValue("entryUUID"),
							CreatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("createTimestamp")),
							UpdatedAt:  util.SafeParseTime("20060102150405Z", entry.GetAttributeValue("modifyTimestamp")),
						},
					})
					continue
				}
				// If username or email does not match, mark as new user (do not return ID field)
				users = append(users, model.User{
					LDAPDN:   entry.DN,
					Status:   "active",
					Username: entry.GetAttributeValue(settings.UserAttr),
					Email:    entry.GetAttributeValue(settings.EmailAttr),
					FullName: entry.GetAttributeValue(settings.DisplayNameAttr),
				})
			}
		}

		return users, nil
	}
	ldapClient, err := s.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to get LDAP client: %v", err)
	}

	defer ldapClient.Close()

	users := []model.User{}
	err = db.Session(ctx).Transaction(func(tx *gorm.DB) error {
		for _, userDN := range userDNs {
			searchReq := ldap.NewSearchRequest(
				userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
				"(objectClass=*)",
				[]string{ldapClient.GetOptions().UserAttr, ldapClient.GetOptions().EmailAttr, ldapClient.GetOptions().DisplayNameAttr, "entryUUID", "createTimestamp", "modifyTimestamp"},
				nil,
			)
			result, err := ldapClient.Search(searchReq)
			if err != nil {
				return fmt.Errorf("Failed to search LDAP user: %v", err)
			}
			if len(result.Entries) == 0 {
				return fmt.Errorf("User not found: %s", userDN)
			}
			entry := result.Entries[0]
			user := model.User{
				Username: entry.GetAttributeValue(ldapClient.GetOptions().UserAttr),
				Email:    entry.GetAttributeValue(ldapClient.GetOptions().EmailAttr),
				FullName: entry.GetAttributeValue(ldapClient.GetOptions().DisplayNameAttr),
				Status:   consolemodel.UserStatusActive,
				Source:   consolemodel.UserSourceLDAP,
				LDAPDN:   entry.DN,
			}

			var existingUser model.User
			if err := tx.Where("ldap_dn = ?", entry.DN).First(&existingUser).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					return fmt.Errorf("Failed to check existing user: %v", err)
				}
			} else if existingUser.ResourceID != "" {
				// If already exists, return error
				return fmt.Errorf("User already exists: %s", user.Username)
			}
			if err := tx.Where("username = ? or email = ?", entry.GetAttributeValue(settings.UserAttr), entry.GetAttributeValue(settings.EmailAttr)).Order("username").First(&existingUser).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					level.Error(logger).Log("msg", "Failed to check existing user", "err", err.Error())
					return fmt.Errorf("failed to check existing user: %w", err)
				}
			} else if existingUser.ResourceID != "" {
				// If username or email matches, bind
				existingUser.LDAPDN = user.LDAPDN
				if err := tx.Select("LDAPDN").Updates(&existingUser).Error; err != nil {
					return fmt.Errorf("failed to update user: %w", err)
				}

			} else {
				if err := tx.Create(&user).Error; err != nil {
					return fmt.Errorf("Failed to create user: %v", err)
				}
			}

			users = append(users, user)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return users, nil

}

func (s *UserService) RestoreUser(ctx context.Context, userID string) error {
	logger := log.GetContextLogger(ctx)
	dbConn := db.Session(ctx)
	var user model.User
	if err := dbConn.Model(&model.User{}).Unscoped().Where("resource_id = ?", userID).First(&user).Error; err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if !user.DeletedAt.Valid {
		return errors.New("user is not deleted")
	}
	err := dbConn.Model(&user).Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Select("Status", "DeletedAt").Updates(map[string]any{
			"status":     consolemodel.UserStatusActive,
			"deleted_at": nil,
		}).Error; err != nil {
			return fmt.Errorf("failed to restore user: %w", err)
		}
		if user.Source != consolemodel.UserSourceLocal && user.LDAPDN != "" {
			settings, err := s.Service.GetLDAPSettings(ctx)
			if err != nil {
				return fmt.Errorf("failed to get LDAP settings: %w", err)
			}
			level.Info(logger).Log("msg", "restore ldap entry", "username", user.Username, "email", user.Email, "full_name", user.FullName, "ldap_dn", user.LDAPDN)
			ldapSession, err := s.Service.GetLDAPSession(ctx)
			if err != nil {
				return fmt.Errorf("failed to get LDAP session: %w", err)
			}
			defer ldapSession.Close()
			level.Debug(logger).Log("msg", "check if ldap entry exists", "username", user.Username, "email", user.Email, "full_name", user.FullName, "ldap_dn", user.LDAPDN)
			entry, err := s.GetLDAPEntry(ctx, user.LDAPDN, []string{"entryUUID", "createTimestamp", "modifyTimestamp"})
			if err != nil {
				return fmt.Errorf("failed to get LDAP entry: %w", err)
			}
			if entry == nil {
				level.Info(logger).Log("msg", "create ldap entry", "username", user.Username, "email", user.Email, "full_name", user.FullName, "ldap_dn", user.LDAPDN)
				var request = ldap.NewAddRequest(user.LDAPDN, nil)

				var attrs map[string][]string = map[string][]string{
					"cn":                     {user.Username},
					"sn":                     {user.FullName},
					"objectClass":            {"top", "organizationalPerson", "inetOrgPerson"},
					settings.UserAttr:        {user.Username},
					settings.DisplayNameAttr: {user.FullName},
					settings.EmailAttr:       {user.Email},
				}
				for name, values := range attrs {
					request.Attribute(name, values)
				}
				if err := ldapSession.Add(request); err != nil {
					return fmt.Errorf("failed to create LDAP entry: %w", err)
				}
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to restore user: %w", err)
	}
	middleware.DeleteUserCache(user.ResourceID)

	return nil
}

func (s *UserService) GetUserApplications(ctx context.Context, userID string) ([]model.UserApplication, error) {
	dbConn := db.Session(ctx)
	var applications []model.UserApplication
	if err := dbConn.Model(&model.Application{}).
		Select("t_application.*,t_application_user_role.role_id,t_application_role.name as role").
		Joins("JOIN t_application_user_role ON t_application.resource_id = t_application_user_role.application_id and t_application_user_role.deleted_at is null").
		Joins("LEFT JOIN t_application_role ON t_application_role.resource_id = t_application_user_role.role_id and t_application_role.deleted_at is null").
		Joins("JOIN t_user ON t_user.resource_id = t_application_user_role.user_id and t_user.deleted_at is null").
		Where("t_user.resource_id = ? and t_application.deleted_at is null", userID).
		Find(&applications).Error; err != nil {
		return nil, fmt.Errorf("failed to get applications: %w", err)
	}
	return applications, nil
}
