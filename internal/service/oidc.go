package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/sven-victor/ez-console/pkg/util/jwt"

	"github.com/go-ldap/ldap/v3"
	"github.com/sven-victor/ez-auth/internal/model"
	"github.com/sven-victor/ez-console/pkg/config"
	"github.com/sven-victor/ez-console/pkg/db"
	"github.com/sven-victor/ez-console/pkg/middleware"
	"github.com/sven-victor/ez-console/pkg/util"
	"github.com/sven-victor/ez-console/server"
	"github.com/sven-victor/ez-utils/log"
	"github.com/sven-victor/ez-utils/sets"
	"gorm.io/gorm"
)

type OIDCService struct {
	server.Service
}

func NewOIDCService(svc server.Service) *OIDCService {
	return &OIDCService{
		Service: svc,
	}
}

func (s *OIDCService) GetApplicationKey(ctx context.Context, clientID string) (*model.ApplicationKey, error) {
	var key model.ApplicationKey
	if err := db.Session(ctx).Select("t_application_key.*").Where("client_id = ?", clientID).
		Joins("JOIN t_application on t_application.resource_id = t_application_key.application_id").
		Where("t_application.status = ? and t_application.deleted_at is null", "active").
		First(&key).Error; err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}
	return &key, nil
}

func (s *OIDCService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*model.ApplicationKey, error) {
	key, err := s.GetApplicationKey(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials: %w", err)
	}
	secret, err := key.ClientSecret.UnsafeString()
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret: %w", err)
	}
	if secret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}
	return key, nil
}

type RoleApplication struct {
	model.Application
	Role   string `json:"role"`
	RoleID string `json:"role_id"`
}

func (s *OIDCService) Authorize(ctx context.Context, clientID string, user *model.OIDCUserInfo, scopeList []string) (*model.Application, error) {
	if user.LDAPDN == "" {
		return nil, fmt.Errorf("user not found")
	}

	settings, err := s.Service.GetLDAPSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}
	if !settings.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}

	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	// Get application and role information from database based on clientID
	var app RoleApplication
	if err := db.Session(ctx).Model(&model.Application{}).
		Select("t_application.*, t_application_role.name as role, t_application_role.resource_id as role_id").
		Joins("left join t_application_key on t_application.resource_id = t_application_key.application_id").
		Joins("left join t_application_user_role on t_application.resource_id = t_application_user_role.application_id and t_application_user_role.user_id = ?", user.Sub).
		Joins("left join t_application_role on t_application.resource_id = t_application_role.application_id  and t_application_user_role.role_id = t_application_role.resource_id").
		Where("t_application_key.client_id = ? and t_application.status = ? and t_application.deleted_at is null", clientID, "active").
		Find(&app).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrorResponse{
				HTTPCode: http.StatusNotFound,
				Code:     "E4041",
				Message:  "application not found",
			}
		}
		return nil, fmt.Errorf("failed to get application: %w", err)
	}
	if app.LDAPDN == "" {
		return nil, fmt.Errorf("application LDAPDN is empty")
	}

	entry, err := s.Service.GetLDAPEntry(ctx, app.LDAPDN, []string{"member", "uniqueMember", "objectClass"})
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP entry: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("application not found")
	}
	var memberList []string
	if slices.Contains(entry.GetAttributeValues("objectClass"), "groupOfUniqueNames") {
		memberList = entry.GetAttributeValues("uniqueMember")
	} else if slices.Contains(entry.GetAttributeValues("objectClass"), "groupOfNames") {
		memberList = entry.GetAttributeValues("member")
	}
	if !slices.Contains(memberList, user.LDAPDN) {
		return nil, fmt.Errorf("user not found in application")
	}
	var appAuthorization model.ApplicationAuthorization
	// If application authorization doesn't exist, create it; otherwise update it
	db.Session(ctx).Where("user_id = ? AND application_id = ?", user.Sub, app.ResourceID).First(&appAuthorization)
	if appAuthorization.ResourceID == "" {
		db.Session(ctx).Create(&model.ApplicationAuthorization{
			UserID:        user.Sub,
			ApplicationID: app.ResourceID,
			Scopes:        scopeList,
		})
	} else {
		db.Session(ctx).
			Where("resource_id = ?", appAuthorization.ResourceID).
			Select("scopes").
			Updates(&model.ApplicationAuthorization{Scopes: scopeList})
	}
	user.Role = app.Role
	user.RoleID = app.RoleID
	user.ApplicationID = app.ResourceID
	return &app.Application, nil
}

// GetUserInfo retrieves user information
func (s *OIDCService) GetUserInfo(ctx context.Context, sessionID string, appID string) (*model.OIDCUserInfo, error) {
	ldapSession, err := s.Service.GetLDAPSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP session: %w", err)
	}
	defer ldapSession.Close()

	var user model.User
	if err := db.Session(ctx).Select("t_user.*,t_application_role.name as role,t_application_user_role.role_id").Model(&model.User{}).Joins("join t_session on t_user.resource_id = t_session.user_id").
		Joins("LEFT JOIN t_application_user_role on t_user.resource_id = t_application_user_role.user_id and t_application_user_role.application_id = ?", appID).
		Joins("LEFT JOIN t_application_role on t_application_role.resource_id = t_application_user_role.role_id and t_application_role.application_id = ?", appID).
		Joins("JOIN t_application on t_application.resource_id = t_application_user_role.application_id").
		Where("t_session.resource_id = ? and t_application.status = ? and t_application.deleted_at is null", sessionID, "active").
		First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user.LDAPDN != "" {
		settings, err := s.Service.GetLDAPSettings(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get LDAP settings: %w", err)
		}
		// Get user LDAP information
		searchRequest := ldap.NewSearchRequest(
			user.LDAPDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{settings.DisplayNameAttr, settings.EmailAttr},
			nil,
		)

		result, err := ldapSession.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to search user: %w", err)
		}

		if len(result.Entries) == 0 {
			return nil, fmt.Errorf("user not found")
		}
		user.Email = result.Entries[0].GetAttributeValue(settings.EmailAttr)
		user.FullName = result.Entries[0].GetAttributeValue(settings.DisplayNameAttr)

	}
	return &model.OIDCUserInfo{
		Sub:               user.ResourceID,
		Name:              user.FullName,
		Email:             user.Email,
		PreferredUsername: user.Username,
		Picture:           user.Avatar,
		LDAPDN:            user.LDAPDN,
		Role:              user.Role,
		RoleID:            user.RoleID,
	}, nil
}

// GetJWKS retrieves JSON Web Key Set
func (s *OIDCService) GetJWKS(ctx context.Context, appID string) (*model.JWKS, error) {
	logger := log.GetContextLogger(ctx)
	privateKeys, err := s.GetPrivateKeys(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	if len(privateKeys) == 0 {
		var privateKey model.ApplicationPrivateKey
		globalJWT := config.GetConfig().JWT
		switch k := globalJWT.PrivateKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, []byte:
			privateKey.Algorithm = globalJWT.Algorithm.Alg()
			privateKey.SetPrivateKey(k)
		case string:
			privateKey.Algorithm = globalJWT.Algorithm.Alg()
			privateKey.SetPrivateKey([]byte(k))
		default:
			return nil, fmt.Errorf("invalid global private key type: %T", k)
		}
		privateKeys = append(privateKeys, privateKey)
	}
	keys := make([]model.JWK, 0, len(privateKeys))
	for _, key := range privateKeys {
		pk, err := key.GetPrivateKey()
		if err != nil {
			level.Error(logger).Log("msg", "failed to get private key", "error", err)
			continue
		}
		switch privKey := pk.(type) {
		case *rsa.PrivateKey:
			pubKey := privKey.PublicKey
			var e []byte
			e = make([]byte, 4)
			binary.BigEndian.PutUint32(e, uint32(pubKey.E))
			switch privKey.Size() {
			case 256, 384, 512:
			default:
				level.Error(logger).Log("msg", "unsupported RSA key size", "size", privKey.Size())
				continue
			}
			keys = append(keys, model.JWK{
				Kty: "RSA",
				Alg: fmt.Sprintf("RS%d", privKey.Size()),
				Use: "sig",
				Kid: key.ResourceID,
				Crv: "RSA",
				N:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pubKey.N.Bytes()),
				E:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(e[1:]),
			})

		case *ecdsa.PrivateKey:
			switch privKey.Curve.Params().BitSize {
			case 256, 384, 521:
			default:
				level.Error(logger).Log("msg", "unsupported ECDSA key size", "size", privKey.Curve.Params().BitSize)
				continue
			}
			pubKey := privKey.PublicKey
			keys = append(keys, model.JWK{
				Kty: "EC",
				Use: "sig",
				Alg: "ES" + strconv.Itoa(pubKey.Curve.Params().BitSize),
				Kid: key.ResourceID,
				Crv: pubKey.Curve.Params().Name,
				X:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pubKey.X.Bytes()),
				Y:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pubKey.Y.Bytes()),
			})
		}
	}
	return &model.JWKS{
		Keys: keys,
	}, nil
}

var ResponseTypesSupported = []string{
	"code",
	"token",
	"id_token",
	"code token",
	"code id_token",
	"token id_token",
	"code token id_token",
}

func (s *OIDCService) GetPrivateKeys(ctx context.Context, appID string) ([]model.ApplicationPrivateKey, error) {
	dbConn := db.Session(ctx)
	var privateKeys []model.ApplicationPrivateKey
	if err := dbConn.Select("t_application_private_key.*").Where("application_id = ?", appID).
		Joins("JOIN t_application on t_application.resource_id = t_application_private_key.application_id").
		Where("t_application.status = ? and t_application.deleted_at is null", "active").
		Find(&privateKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	return privateKeys, nil
}

func (s *OIDCService) GetJWTIssuer(ctx context.Context, appID string, alg string, keyID string) (*jwt.Config, error) {
	logger := log.GetContextLogger(ctx)
	// Prioritize using application private key for signing
	privateKeys, err := s.GetPrivateKeys(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	if len(privateKeys) > 0 {
		for _, key := range privateKeys {
			if keyID != "" {
				if key.ResourceID == keyID {
					pk, err := key.GetPrivateKey()
					if err != nil {
						return nil, fmt.Errorf("failed to get private key: %w", err)
					}
					var pubKey crypto.PublicKey
					switch privKey := pk.(type) {
					case *rsa.PrivateKey:
						pubKey = &privKey.PublicKey
						switch privKey.Size() {
						case 256, 384, 512:
						default:
							return nil, fmt.Errorf("unsupported RSA key size: %d", privKey.Size())
						}
					case *ecdsa.PrivateKey:
						pubKey = &privKey.PublicKey
						switch privKey.Curve.Params().BitSize {
						case 256, 384, 521:
						default:
							return nil, fmt.Errorf("unsupported ECDSA key size: %d", privKey.Curve.Params().BitSize)
						}
					case []byte:
					default:
						return nil, fmt.Errorf("unsupported private key type: %T", pk)
					}

					return &jwt.Config{
						PrivateKey: pk,
						PublicKey:  pubKey,
						Algorithm:  key.GetAlgorithm(),
						KeyID:      key.ResourceID,
					}, nil
				}
				continue
			}
			pk, err := key.GetPrivateKey()
			if err != nil {
				level.Error(logger).Log("msg", "failed to get private key", "error", err)
				continue
			}
			switch privKey := pk.(type) {
			case *rsa.PrivateKey:
				if alg == "" || strings.HasPrefix(alg, "RS") {
					switch privKey.Size() {
					case 256, 384, 512:
					default:
						level.Error(logger).Log("msg", "unsupported RSA key size", "size", privKey.Size())
						continue
					}
					if alg != "" && fmt.Sprintf("RS%d", privKey.Size()) != alg {
						continue
					}
					return &jwt.Config{
						PrivateKey: privKey,
						PublicKey:  privKey.PublicKey,
						Algorithm:  key.GetAlgorithm(),
						KeyID:      key.ResourceID,
					}, nil
				}
			case *ecdsa.PrivateKey:
				if alg == "" || strings.HasPrefix(alg, "ES") {
					if alg != "" && fmt.Sprintf("ES%d", privKey.Curve.Params().BitSize) != alg {
						continue
					}
					switch privKey.Curve.Params().BitSize {
					case 256, 384, 521:
					default:
						level.Error(logger).Log("msg", "unsupported ECDSA key size", "size", privKey.Curve.Params().BitSize)
						continue
					}

					return &jwt.Config{
						PrivateKey: privKey,
						Algorithm:  key.GetAlgorithm(),
						KeyID:      key.ResourceID,
						PublicKey:  privKey.PublicKey,
					}, nil
				}
			case []byte:
				if alg == "" || strings.HasPrefix(alg, "HS") {
					if alg != "" && key.Algorithm != alg {
						continue
					}
					return &jwt.Config{
						PrivateKey: privKey,
						Algorithm:  key.GetAlgorithm(),
						KeyID:      key.ResourceID,
					}, nil
				}
			}
		}
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	return &config.GetConfig().JWT, nil
}

// GetOpenIDConfiguration retrieves OpenID configuration
func (s *OIDCService) GetOpenIDConfiguration(ctx *gin.Context, clientID string) (*model.OpenIDConfiguration, error) {
	logger := log.GetContextLogger(ctx)
	dbConn := db.Session(ctx)
	var app model.Application
	if err := dbConn.Select("t_application.*").
		Joins("left join t_application_key on t_application.resource_id = t_application_key.application_id").
		Where("t_application_key.client_id = ? and t_application.status = ? and t_application.deleted_at is null", clientID, "active").
		First(&app).Error; err != nil {
		return nil, fmt.Errorf("failed to get application: %w", err)
	}

	rootURL := util.GetRootURL(ctx)

	privateKeys, err := s.GetPrivateKeys(ctx, app.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	if len(privateKeys) == 0 {
		var privateKey model.ApplicationPrivateKey
		globalJWT := config.GetConfig().JWT
		privateKey.Algorithm = globalJWT.Algorithm.Alg()
		switch pk := globalJWT.PrivateKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			privateKey.SetPrivateKey(pk)
			privateKey.SetPrivateKey(pk)
		default:
			return nil, fmt.Errorf("invalid global private key type: %T", pk)
		}
		privateKeys = append(privateKeys, privateKey)

	}

	idTokenSigningAlgValuesSupported := sets.New[string]()

	for _, privateKey := range privateKeys {
		switch privateKey.Algorithm {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512":
			idTokenSigningAlgValuesSupported.Insert(privateKey.Algorithm)
		default:
			level.Error(logger).Log("msg", "unsupported algorithm", "algorithm", privateKey.Algorithm)
			continue
		}
	}

	return &model.OpenIDConfiguration{
		Issuer:                           rootURL,
		AuthorizationEndpoint:            rootURL + "/ui/oidc/authorize",
		TokenEndpoint:                    rootURL + "/api/oauth2/token",
		UserinfoEndpoint:                 rootURL + "/api/oauth2/userinfo",
		JWKSURI:                          rootURL + "/api/oauth2/.well-known/jwks/" + app.ResourceID,
		ResponseTypesSupported:           ResponseTypesSupported,
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: idTokenSigningAlgValuesSupported.List(),
		ScopesSupported:                  app.Scopes,
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		ClaimsSupported: []string{
			"sub",
			"name",
			"preferred_username",
			"email",
			"role",
			"role_id",
		},
	}, nil
}

func (s *OIDCService) GetApplicationAuthorizationByClientID(ctx context.Context, clientID string) (*model.ApplicationAuthorization, error) {
	dbConn := db.Session(ctx)
	userID := middleware.GetUserIDFromContext(ctx)
	if len(userID) == 0 {
		return nil, util.NewError("E4011", "user not found")
	}
	var app model.Application
	if err := dbConn.Select([]string{
		"t_application.resource_id",
		"t_application.name",
		"t_application.display_name",
		"t_application.display_name_i18n",
		"t_application.description",
		"t_application.description_i18n",
		"t_application.icon",
		"t_application.status",
		"t_application.scopes",
	}).
		Joins("left join t_application_key on t_application.resource_id = t_application_key.application_id").
		Where("t_application_key.client_id = ? and t_application.status = ? and t_application.deleted_at is null", clientID, "active").
		First(&app).Error; err != nil {
		return nil, fmt.Errorf("failed to get application: %w", err)
	}
	appAuthorization := model.ApplicationAuthorization{
		UserID:        userID,
		ApplicationID: app.ResourceID,
		Application:   &app,
	}
	if err := dbConn.Where("user_id = ? and application_id = ?", userID, app.ResourceID).First(&appAuthorization).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to get application authorization: %w", err)
		}
	}
	return &appAuthorization, nil
}
