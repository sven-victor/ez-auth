package model

import (
	"github.com/sven-victor/ez-console/pkg/model"
)

// OIDCToken OIDC token model
type OIDCToken struct {
	model.Base
	ClientID    string `gorm:"type:varchar(100);not null" json:"client_id"`
	UserID      string `gorm:"type:varchar(36);not null" json:"user_id"`
	AccessToken string `gorm:"type:varchar(1000);not null" json:"access_token"`
	TokenType   string `gorm:"type:varchar(20);not null" json:"token_type"`
	ExpiresIn   int64  `gorm:"not null" json:"expires_in"`
	Scope       string `gorm:"type:varchar(100)" json:"scope"`
}

// OIDCUserInfo OIDC user information model
type OIDCUserInfo struct {
	Sub                 string   `json:"sub,omitempty"`
	Name                string   `json:"name,omitempty"`
	PreferredUsername   string   `json:"preferred_username,omitempty"`
	Email               string   `json:"email,omitempty"`
	Role                string   `json:"role,omitempty"`
	RoleID              string   `json:"role_id,omitempty"`
	Picture             string   `json:"picture,omitempty"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
	Exp                 int64    `json:"exp,omitempty"`
	Iat                 int64    `json:"iat,omitempty"`
	SessionID           string   `json:"sid,omitempty"`
	Aud                 []string `json:"aud,omitempty"`
	ApplicationID       string   `json:"application_id,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	// Not exported
	LDAPDN string `gorm:"-" json:"-"`

	GrantTypes []string `json:"grant_types,omitempty"`
}

func (u *OIDCUserInfo) GetByScope(scopeList []string) map[string]any {
	oidcUserInfo := map[string]any{}
	if len(scopeList) == 0 || scopeList[0] == "" {
		scopeList = []string{"openid", "preferred_username", "email", "profile", "role"}
	}
	oidcUserInfo["sid"] = u.SessionID
	oidcUserInfo["grant_types"] = u.GrantTypes
	for _, scope := range scopeList {
		switch scope {
		case "openid":
			oidcUserInfo["sub"] = u.Sub
		case "username":
			oidcUserInfo["username"] = u.PreferredUsername
		case "preferred_username":
			oidcUserInfo["preferred_username"] = u.PreferredUsername
		case "email":
			oidcUserInfo["email"] = u.Email
		case "profile":
			oidcUserInfo["name"] = u.Name
			oidcUserInfo["preferred_username"] = u.PreferredUsername
			oidcUserInfo["picture"] = u.Picture
		case "role", "roles":
			oidcUserInfo["role"] = u.Role
			oidcUserInfo["role_id"] = u.RoleID
		}
	}
	oidcUserInfo["nonce"] = u.Nonce

	for key, value := range oidcUserInfo {
		if value == nil || value == "" {
			delete(oidcUserInfo, key)
		}
	}

	return oidcUserInfo
}

type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}
