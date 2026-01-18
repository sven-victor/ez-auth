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

// Package api provides HTTP API controllers for the ez-auth service.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sven-victor/ez-utils/log"
	w "github.com/sven-victor/ez-utils/wrapper"

	"github.com/sven-victor/ez-auth/internal/model"
	"github.com/sven-victor/ez-auth/internal/service"
	"github.com/sven-victor/ez-console/pkg/middleware"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-console/pkg/util"
	"github.com/sven-victor/ez-console/server"
)

// OIDCController handles OpenID Connect (OIDC) related HTTP requests.
// It provides endpoints for OIDC discovery, token management, and client management.
type OIDCController struct {
	svc *service.OIDCService
}

func (c *OIDCController) RegisterRoutes(ctx context.Context, router *gin.RouterGroup) {
	oauth2 := router.Group("/oauth2")
	{
		// well-known endpoints
		wellknown := oauth2.Group("/.well-known")
		middleware.WithoutAuthentication(wellknown)
		// OIDC discovery endpoints
		wellknown.GET("/openid-configuration/:client_id", c.GetOpenIDConfiguration)
		wellknown.GET("/openid-configuration", c.GetOpenIDConfiguration)
		wellknown.GET("/jwks/:id", c.GetJWKS)
		wellknown.GET("/jwks", c.GetJWKS)

		// OAuth2 endpoints
		oauth2.GET("/applications/client_id/:client_id", c.GetApplicationByClientID)
		oauth2.GET("/authorize", c.Authorize)
		middleware.WithAuthentication(oauth2.Group("/token"), middleware.NonAuthentication).POST("", c.Token)
		middleware.WithAuthentication(oauth2.Group("/userinfo"), middleware.NonAuthentication).GET("", c.UserInfo)
	}

	oidc := router.Group("/oidc/test")
	oidc.POST("", c.TestOIDCConfig)
}

// GetOpenIDConfiguration retrieves the OpenID Connect configuration.
// @Summary Get OpenID configuration
// @Description Retrieves the OpenID Connect configuration information
// @Tags OIDC
// @Accept json
// @Produce json
// @Success 200 {object} model.OpenIDConfiguration
// @Failure 500 {object} util.ErrorResponse
// @Router /api/oauth2/.well-known/openid-configuration [get]
func (c *OIDCController) GetOpenIDConfiguration(ctx *gin.Context) {
	clientID := ctx.Param("client_id")
	if clientID == "" {
		clientID = ctx.Query("client_id")
	}
	config, err := c.svc.GetOpenIDConfiguration(ctx, clientID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to get OpenID configuration",
		})
		return
	}

	ctx.JSON(http.StatusOK, config)
}

// GetJWKS retrieves the JSON Web Key Set (JWKS).
// @Summary Get JWKS
// @Description Retrieves the JSON Web Key Set for token validation
// @Tags OIDC
// @Accept json
// @Produce json
// @Success 200 {object} model.JWKS
// @Failure 500 {object} util.ErrorResponse
// @Router /api/oauth2/.well-known/jwks.json [get]
func (c *OIDCController) GetJWKS(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		id = ctx.Query("id")
	}
	jwks, err := c.svc.GetJWKS(ctx, id)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to get JWKS",
		})
		return
	}

	ctx.JSON(http.StatusOK, jwks)
}

// Authorize handles OAuth2 authorization requests.
// @Summary Get OAuth2 authorization
// @Description Handles OAuth2 authorization requests with client credentials grant type
// @Tags OIDC
// @Accept json
// @Produce json
// @Param client_id formData string true "Client ID"
// @Param redirect_uri formData string true "Redirect URI"
// @Param response_type formData string true "Response type (code)"
// @Param scope formData string false "Requested scope"
// @Param code_challenge formData string false "Code challenge"
// @Param code_challenge_method formData string false "Code challenge method"
// @Param state formData string false "State"
// @Param nonce formData string false "Nonce"
// @Success 302 {string} string "Redirect to the redirect URI"
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/oauth2/authorize [get]
func (c *OIDCController) Authorize(ctx *gin.Context) {
	nonce := ctx.Query("nonce")
	clientID := ctx.Query("client_id")
	alg := ctx.Query("id_token_signed_response_alg")
	redirectURI, err := url.Parse(ctx.Query("redirect_uri"))
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      err,
			Message:  "invalid redirect URI",
		})
		return
	}
	redirectURIQuery := redirectURI.Query()

	responseType := ctx.Query("response_type")
	if !slices.Contains(service.ResponseTypesSupported, responseType) {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      nil,
			Message:  fmt.Sprintf("unsupported response type: %s", responseType),
		})
		return
	}
	user, ok := ctx.Value("user").(consolemodel.User)
	if !ok {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusForbidden,
			Code:     "E4031",
			Err:      nil,
			Message:  "user not authenticated",
		})
		return
	}
	scopeList := strings.Split(ctx.Query("scope"), " ")

	sessionID := ctx.Value("session_id").(string)
	if len(sessionID) == 0 {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusForbidden,
			Code:     "E4031",
			Err:      nil,
			Message:  "session not found",
		})
		return
	}
	oidcUser := model.OIDCUserInfo{
		Sub:               user.ResourceID,
		Name:              user.FullName,
		Email:             user.Email,
		PreferredUsername: user.Username,
		Picture:           user.Avatar,
		LDAPDN:            user.LDAPDN,
		SessionID:         sessionID,
		Aud:               []string{clientID},
		ApplicationID:     "",
		Nonce:             nonce,
	}

	app, err := c.svc.Authorize(ctx, clientID, &oidcUser, scopeList)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusForbidden,
			Code:     "E4031",
			Err:      err,
			Message:  "failed to authorize",
		})
		return
	}
	if !app.CheckRedirectURI(redirectURI.String()) {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusForbidden,
			Code:     "E4031",
			Message:  "invalid redirect URI",
		})
		return
	}
	if !slices.Contains(app.GrantTypes, string(model.ApplicationGrantTypeAuto)) {
		responseType = ""
	loop:
		for _, grantType := range app.GrantTypes {
			switch model.ApplicationGrantType(grantType) {
			case model.ApplicationGrantTypeAuthorizationCode:
				responseType = "code"
				break loop
			case model.ApplicationGrantTypeImplicit:
				responseType = "token id_token"
				break loop
			case model.ApplicationGrantTypeHybrid:
				responseType = "code id_token"
				break loop
			default:
			}
		}
		if responseType == "" {
			util.RespondWithError(ctx, util.ErrorResponse{
				HTTPCode: http.StatusForbidden,
				Code:     "E4031",
				Message:  "unsupported grant type",
			})
			return
		}
	}
	oidcUser.ApplicationID = app.ResourceID
	oidcUser.GrantTypes = app.GrantTypes
	oidcUserInfo := oidcUser.GetByScope(scopeList)
	oidcUserInfo["aud"] = []string{clientID}
	err = c.svc.StartAudit(ctx, app.ResourceID, func(auditLog *consolemodel.AuditLog) error {
		auditLog.Action = "oidc:authorize"
		auditLog.ActionName = "Authorize"
		auditLog.Details.Request = map[string]any{
			"client_id":     clientID,
			"redirect_uri":  redirectURI.String(),
			"response_type": responseType,
			"scope":         scopeList,
		}
		for _, rt := range strings.Split(responseType, " ") {
			switch rt {
			case "none", "code":
				codeChallenge := ctx.Query("code_challenge")
				codeChallengeMethod := ctx.Query("code_challenge_method")
				if len(codeChallenge) > 0 {
					oidcUserInfo["code_challenge"] = codeChallenge
					oidcUserInfo["code_challenge_method"] = codeChallengeMethod
				}

				state := ctx.Query("state")
				if state == "" {
					return util.NewErrorMessage("E4001", "state is required")
				}
				randomCode := util.GenerateRandomString(20)
				_, err := c.svc.CreateCache(ctx, fmt.Sprintf("ez-auth:oidc:code:%s", randomCode), w.JSONStringer(oidcUserInfo).String(), time.Now().Add(time.Minute*10))
				if err != nil {
					return util.NewErrorMessage("E5001", "failed to create cache", err)
				}
				redirectURIQuery.Add("code", randomCode)
				redirectURIQuery.Add("state", state)
			case "token":
				accessToken, err := c.createAccessToken(ctx, clientID, alg, oidcUser)
				if err != nil {
					return util.NewErrorMessage("E5001", "failed to create access token", err)
				}
				redirectURIQuery.Add("access_token", accessToken)
			case "id_token":
				idToken, err := c.createIDToken(ctx, clientID, app.ResourceID, alg, oidcUserInfo)
				if err != nil {
					return util.NewErrorMessage("E5001", "failed to create id token", err)
				}
				redirectURIQuery.Add("id_token", idToken)
			default:
				return util.NewErrorMessage("E4001", fmt.Sprintf("unsupported response type: %s(%s)", rt, responseType))
			}
		}
		redirectURIQuery.Set("grant_type", "authorization_code")
		redirectURI.RawQuery = redirectURIQuery.Encode()
		// if Accept is application/json, return json format
		if accept := ctx.Request.Header.Get("Accept"); strings.Contains(accept, "application/json") {
			util.RespondWithSuccess(ctx, http.StatusOK, map[string]any{
				"redirect_uri": redirectURI.String(),
			})
			return nil
		}

		ctx.Redirect(http.StatusFound, redirectURI.String())
		return nil

	})
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusInternalServerError,
			Code:     "E5001",
			Err:      err,
			Message:  "failed to start audit",
		})
		return
	}
}

type TokenRequest struct {
	GrantType                string `form:"grant_type" binding:"required" json:"grant_type"`
	ClientID                 string `form:"client_id" json:"client_id"`
	ClientSecret             string `form:"client_secret" json:"client_secret"`
	Code                     string `form:"code" json:"code"`
	CodeVerifier             string `form:"code_verifier" json:"code_verifier"`
	Scope                    string `form:"scope" json:"scope"`
	IDTokenSignedResponseAlg string `form:"id_token_signed_response_alg" json:"id_token_signed_response_alg"`

	// only for refresh token grant type
	RefreshToken string `form:"refresh_token" json:"refresh_token"`

	// only for password grant type
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
}

// Token handles OAuth2 token requests.
// @Summary Get OAuth2 token
// @Description Handles OAuth2 token requests with client credentials grant type
// @Tags OIDC
// @Accept json,x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant type (client_credentials)"
// @Param client_id formData string true "Client ID"
// @Param client_secret formData string true "Client secret"
// @Param code formData string false "Authorization code"
// @Param code_verifier formData string false "Code verifier"
// @Param scope formData string false "Requested scope"
// @Success 200 {object} model.OIDCToken
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/oauth2/token [post]
func (c *OIDCController) Token(ctx *gin.Context) {
	logger := log.GetContextLogger(ctx)
	var tokenRequest TokenRequest
	err := ctx.ShouldBind(&tokenRequest)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request",
		})
		return
	}
	if tokenRequest.ClientID == "" {
		tokenRequest.ClientID, tokenRequest.ClientSecret, _ = ctx.Request.BasicAuth()
	}

	if tokenRequest.ClientID == "" {
		util.RespondWithError(ctx, util.NewErrorMessage("E4001", "client_id is required"))
		return
	}
	if tokenRequest.ClientSecret == "" {
		util.RespondWithError(ctx, util.NewErrorMessage("E4001", "client_secret is required"))
		return
	}

	if len(tokenRequest.Scope) == 0 {
		tokenRequest.Scope = "openid email username"
	}

	// validate client
	appKey, err := c.svc.ValidateClient(ctx, tokenRequest.ClientID, tokenRequest.ClientSecret)
	if err != nil {
		util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid client credentials", err))
		return
	}

	// handle grant type
	switch tokenRequest.GrantType {
	case "authorization_code":
		if len(tokenRequest.Code) == 0 {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "code is required"))
			return
		}
		cacheValue, err := c.svc.GetCache(ctx, fmt.Sprintf("ez-auth:oidc:code:%s", tokenRequest.Code))
		if err != nil || cacheValue == nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid code", err))
			return
		}
		defer c.svc.DeleteCache(ctx, fmt.Sprintf("ez-auth:oidc:code:%s", tokenRequest.Code))
		var oidcUserInfo model.OIDCUserInfo
		err = json.Unmarshal([]byte(cacheValue.Value), &oidcUserInfo)
		if err != nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid code", err))
			return
		}
		switch oidcUserInfo.CodeChallengeMethod {
		case "S256":
			verifierHash := sha256.Sum256([]byte(tokenRequest.CodeVerifier))
			codeChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
			if codeChallenge != oidcUserInfo.CodeChallenge {
				level.Error(logger).Log("msg", "invalid code verifier", "err", fmt.Sprintf("%s!=%s", codeChallenge, oidcUserInfo.CodeChallenge), "code_verifier", tokenRequest.CodeVerifier, "code_challenge_method", oidcUserInfo.CodeChallengeMethod)
				util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid code verifier"))
				return
			}
		case "plain", "":
			if oidcUserInfo.CodeChallenge != "" && tokenRequest.CodeVerifier != oidcUserInfo.CodeChallenge {
				level.Error(logger).Log("msg", "invalid code verifier", "code_challenge", oidcUserInfo.CodeChallenge, "code_verifier", tokenRequest.CodeVerifier)
				util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid code verifier"))
				return
			}
		default:
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "unsupported code challenge method"))
			return
		}
		oidcUserInfo.ApplicationID = appKey.ApplicationID
		accessToken, err := c.createAccessToken(ctx, tokenRequest.ClientID, tokenRequest.IDTokenSignedResponseAlg, oidcUserInfo)
		if err != nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E5001", "failed to create access token", err))
			return
		}
		idToken, err := c.createIDToken(ctx, tokenRequest.ClientID, appKey.ApplicationID, tokenRequest.IDTokenSignedResponseAlg, oidcUserInfo.GetByScope(strings.Split(tokenRequest.Scope, " ")))
		if err != nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E5001", "failed to create id token", err))
			return
		}
		resp := map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   time.Now().Add(time.Minute * 10).Unix(),
			"id_token":     idToken,
		}
		if slices.Contains(oidcUserInfo.GrantTypes, string(model.ApplicationGrantTypeRefreshToken)) {
			resp["refresh_token"], err = c.createRefreshToken(ctx, tokenRequest.ClientID, tokenRequest.IDTokenSignedResponseAlg, oidcUserInfo)
			if err != nil {
				util.RespondWithError(ctx, util.NewErrorMessage("E5001", "failed to create refresh token", err))
				return
			}
		}
		ctx.JSON(http.StatusOK, resp)
		return
	case "refresh_token":
		refreshToken := tokenRequest.RefreshToken
		if len(refreshToken) == 0 {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "refresh token is required"))
			return
		}

		// validate refresh token
		accessToken, err := c.refreshToken(ctx, refreshToken, tokenRequest.ClientID)
		if err != nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid refresh token", err))
			return
		}

		ctx.JSON(http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   time.Now().Add(time.Minute * 10).Unix(),
		})
		return
	case "password":
		if len(tokenRequest.Username) == 0 {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "username is required"))
			return
		}
		if len(tokenRequest.Password) == 0 {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "password is required"))
			return
		}
		oidcUserInfo, err := c.svc.VerifyApplicationPassword(ctx, appKey.ApplicationID, tokenRequest.Username, tokenRequest.Password)
		if err != nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid username or password", err))
			return
		}
		if oidcUserInfo == nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid user"))
			return
		}
		oidcUserInfo.Aud = []string{appKey.ClientID}
		if !slices.Contains(oidcUserInfo.GrantTypes, string(model.ApplicationGrantTypePassword)) {
			util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid grant type"))
			return
		}
		accessToken, err := c.createAccessToken(ctx, tokenRequest.ClientID, tokenRequest.IDTokenSignedResponseAlg, *oidcUserInfo)
		if err != nil {
			util.RespondWithError(ctx, util.NewErrorMessage("E5001", "failed to create access token", err))
			return
		}
		ctx.JSON(http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   time.Now().Add(time.Minute * 10).Unix(),
		})

	default:
		util.RespondWithError(ctx, util.NewErrorMessage("E4001", "unsupported grant type"))
		return
	}
}

// UserInfo retrieves user information for the authenticated user.
// @Summary Get user info
// @Description Retrieves user information for the authenticated user
// @Tags OIDC
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} model.OIDCUserInfo
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/oauth2/userinfo [get]
func (c *OIDCController) UserInfo(ctx *gin.Context) {
	// get user id from context
	// validate access token
	accessToken := strings.TrimPrefix(ctx.GetHeader("Authorization"), "Bearer ")
	if len(accessToken) == 0 {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     nil,
			Message: "access token is required",
		})
	}
	oidcUserInfo, err := c.verifyAccessToken(ctx, accessToken)
	if err != nil {
		util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid access token", err))
		return
	}
	if len(oidcUserInfo.Aud) == 0 || oidcUserInfo.Aud[0] == "" {
		util.RespondWithError(ctx, util.NewErrorMessage("E4001", "invalid access token, audience is empty"))
		return
	}

	// get user info
	userInfo, err := c.svc.GetUserInfo(ctx, oidcUserInfo.SessionID, oidcUserInfo.ApplicationID)
	if err != nil {
		util.RespondWithError(ctx, util.NewErrorMessage("E5001", "failed to get user info", err))
		return
	}

	ctx.JSON(http.StatusOK, userInfo)
}

func init() {
	server.RegisterControllers(func(ctx context.Context, svc server.Service) server.Controller {
		return &OIDCController{
			svc: service.NewOIDCService(svc),
		}
	})
}

func (c *OIDCController) createAccessToken(ctx *gin.Context, clientID string, alg string, oidcUserInfo model.OIDCUserInfo) (string, error) {
	issuer, err := c.svc.GetJWTIssuer(ctx, oidcUserInfo.ApplicationID, alg, "")
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create id token", err)
	}
	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Minute * 10).Unix(),
		"iat": time.Now().Unix(),
		"sid": oidcUserInfo.SessionID,
		"aud": []string{clientID},
		"iss": util.GetRootURL(ctx),
	}
	if oidcUserInfo.Sub != "" {
		claims["sub"] = oidcUserInfo.Sub
	}
	accessToken, err := issuer.SignedString(&claims)
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create access token", err)
	}
	c.svc.CreateCache(ctx, fmt.Sprintf("ez-auth:oidc:access_token:%x", sha256.Sum256([]byte(accessToken))), w.JSONStringer(oidcUserInfo).String(), time.Now().Add(time.Minute*10))
	return accessToken, nil
}

func (c *OIDCController) createRefreshToken(ctx *gin.Context, clientID, alg string, oidcUserInfo model.OIDCUserInfo) (string, error) {

	issuer, err := c.svc.GetJWTIssuer(ctx, oidcUserInfo.ApplicationID, alg, "")
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create id token", err)
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24 * 7).Unix(),
		"iat": time.Now().Unix(),
		"aud": []string{clientID},
		"iss": util.GetRootURL(ctx),
	}
	if oidcUserInfo.Sub != "" {
		claims["sub"] = oidcUserInfo.Sub
	}
	refreshToken, err := issuer.SignedString(&claims)
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create refresh token", err)
	}
	c.svc.CreateCache(ctx, fmt.Sprintf("ez-auth:oidc:refresh_token:%x", sha256.Sum256([]byte(refreshToken))), w.JSONStringer(oidcUserInfo).String(), time.Now().Add(time.Hour*24*7))
	return refreshToken, nil
}

func (c *OIDCController) refreshToken(ctx *gin.Context, refreshToken string, clientID string) (string, error) {
	token, err := jwt.ParseWithClaims(refreshToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		aud, err := token.Claims.GetAudience()
		if err != nil {
			return nil, util.NewErrorMessage("E4001", "invalid refresh token", err)
		}
		if len(aud) == 0 || aud[0] != clientID {
			return nil, util.NewErrorMessage("E4001", "invalid refresh token")
		}
		appKey, err := c.svc.GetApplicationKey(ctx, clientID)
		if err != nil {
			return nil, util.NewErrorMessage("E5001", "failed to get application key", err)
		}
		kid, _ := token.Header["kid"].(string)
		issuer, err := c.svc.GetJWTIssuer(ctx, appKey.ApplicationID, token.Method.Alg(), kid)
		if err != nil {
			return nil, util.NewErrorMessage("E5001", "failed to get jwt issuer", err)
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			return issuer.PublicKey, nil
		case *jwt.SigningMethodHMAC:
			return issuer.PrivateKey, nil
		default:
			return nil, util.NewErrorMessage("E4001", "invalid access token, unsupported algorithm")
		}
	})
	if err != nil {
		return "", util.NewErrorMessage("E4001", fmt.Sprintf("invalid refresh token: %s", err), err)
	}

	// validate access token is expired
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		return "", util.NewErrorMessage("E4001", "invalid refresh token, failed to get expiration time", err)
	}
	if exp.Before(time.Now()) {
		return "", util.NewErrorMessage("E4001", "refresh token expired")
	}

	// validate access token is used before issued
	nbf, err := token.Claims.GetNotBefore()
	if err != nil {
		return "", util.NewErrorMessage("E4001", "invalid refresh token, failed to get not before", err)
	}
	if nbf != nil && nbf.Before(time.Now()) {
		return "", util.NewErrorMessage("E4001", "refresh token used before issued")
	}

	cacheValue, err := c.svc.GetCache(ctx, fmt.Sprintf("ez-auth:oidc:refresh_token:%x", sha256.Sum256([]byte(refreshToken))))
	if err != nil || cacheValue == nil {
		return "", util.NewErrorMessage("E4001", "invalid refresh token, failed to get user info", err)
	}
	var oidcUserInfo model.OIDCUserInfo
	err = json.Unmarshal([]byte(cacheValue.Value), &oidcUserInfo)
	if err != nil {
		return "", util.NewErrorMessage("E4001", "invalid refresh token, failed to load oidc user info", err)
	}
	accessToken, err := c.createAccessToken(ctx, clientID, token.Method.Alg(), oidcUserInfo)
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create access token", err)
	}
	return accessToken, nil
}

func (c *OIDCController) verifyAccessToken(ctx context.Context, accessToken string) (*model.OIDCUserInfo, error) {
	token, err := jwt.ParseWithClaims(accessToken, jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		aud, err := token.Claims.GetAudience()
		if err != nil {
			return nil, util.NewErrorMessage("E4001", "invalid access token, failed to get audience", err)
		}
		if len(aud) == 0 || aud[0] == "" {
			return nil, util.NewErrorMessage("E4001", "invalid access token, audience is empty")
		}
		appKey, err := c.svc.GetApplicationKey(ctx, aud[0])
		if err != nil {
			return nil, util.NewErrorMessage("E5001", "failed to get application key", err)
		}
		kid, _ := token.Header["kid"].(string)
		issuer, err := c.svc.GetJWTIssuer(ctx, appKey.ApplicationID, token.Method.Alg(), kid)
		if err != nil {
			return nil, util.NewErrorMessage("E5001", "failed to get jwt issuer", err)
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			return issuer.PublicKey, nil
		case *jwt.SigningMethodHMAC:
			return issuer.PrivateKey, nil
		default:
			return nil, util.NewErrorMessage("E4001", "invalid access token, unsupported algorithm")
		}
	})
	if err != nil {
		return nil, util.NewErrorMessage("E4001", fmt.Sprintf("invalid access token: %s", err), err)
	}

	// validate access token is expired
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		return nil, util.NewErrorMessage("E4001", "invalid access token, failed to get expiration time", err)
	}
	if exp.Before(time.Now()) {
		return nil, util.NewErrorMessage("E4001", "access token expired")
	}

	// validate access token is used before issued
	nbf, err := token.Claims.GetNotBefore()
	if err != nil {
		return nil, util.NewErrorMessage("E4001", "invalid access token, failed to get not before", err)
	}
	if nbf != nil && nbf.Before(time.Now()) {
		return nil, util.NewErrorMessage("E4001", "access token used before issued")
	}

	cacheValue, err := c.svc.GetCache(ctx, fmt.Sprintf("ez-auth:oidc:access_token:%x", sha256.Sum256([]byte(accessToken))))
	if err != nil || cacheValue == nil {
		return nil, util.NewErrorMessage("E4001", "invalid access token, failed to get user info", err)
	}

	var oidcUserInfo model.OIDCUserInfo
	err = json.Unmarshal([]byte(cacheValue.Value), &oidcUserInfo)
	if err != nil {
		return nil, util.NewErrorMessage("E4001", "invalid access token, failed to load oidc user info", err)
	}
	return &oidcUserInfo, nil
}

func (c *OIDCController) createIDToken(ctx *gin.Context, clientID, appID, alg string, jwtClaims jwt.MapClaims) (string, error) {
	jwtClaims["exp"] = time.Now().Add(time.Minute * 10).Unix()
	jwtClaims["iat"] = time.Now().Unix()
	delete(jwtClaims, "grant_types")
	delete(jwtClaims, "sid")
	issuer, err := c.svc.GetJWTIssuer(ctx, appID, alg, "")
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create id token", err)
	}

	jwtClaims["iss"] = util.GetRootURL(ctx)
	jwtClaims["aud"] = []string{clientID}

	idToken, err := issuer.SignedString(&jwtClaims)
	if err != nil {
		return "", util.NewErrorMessage("E5001", "failed to create id token", err)
	}
	return idToken, nil
}

type TestOIDCConfigRequest struct {
	WellknowEndpoint string `json:"wellknow_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	Code             string `json:"code"`
	CodeVerifier     string `json:"code_verifier"`
	RefreshToken     string `json:"refresh_token"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	AccessToken      string `json:"access_token"`
	JWKSEndpoint     string `json:"jwks_endpoint"`
}

func (c *OIDCController) TestOIDCConfig(ctx *gin.Context) {
	logger := log.GetContextLogger(ctx)
	var req TestOIDCConfigRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request",
		})
	}
	if len(req.WellknowEndpoint) > 0 {
		resp, err := http.Get(req.WellknowEndpoint)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid wellknow endpoint",
			})
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			for _, vv := range v {
				ctx.Header(k, vv)
			}
		}
		io.CopyN(ctx.Writer, resp.Body, 2*1024*1024)
		return
	} else if req.JWKSEndpoint != "" {
		if req.ClientID != "" {
			level.Info(logger).Log("msg", "get jwks by client id", "client_id", req.ClientID)
			appKey, err := c.svc.GetApplicationKey(ctx, req.ClientID)
			if err != nil {
				util.RespondWithError(ctx, util.ErrorResponse{
					Code:    "E4001",
					Err:     err,
					Message: "invalid client id",
				})
			}
			jwks, err := c.svc.GetJWKS(ctx, appKey.ApplicationID)
			if err != nil {
				util.RespondWithError(ctx, util.ErrorResponse{
					Code:    "E4001",
					Err:     err,
					Message: "invalid jwks uri",
				})
			}
			ctx.JSON(http.StatusOK, jwks)
			return
		}
		level.Info(logger).Log("msg", "get jwks by jwks endpoint", "jwks_endpoint", req.JWKSEndpoint)
		resp, err := http.Get(req.JWKSEndpoint)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid jwks uri",
			})
		}
		defer resp.Body.Close()
		io.CopyN(ctx.Writer, resp.Body, 2*1024*1024)
	} else if req.TokenEndpoint != "" {
		level.Info(logger).Log("msg", "token endpoint", "token_endpoint", req.TokenEndpoint)
		tokenRequest, err := http.NewRequest(http.MethodPost, req.TokenEndpoint, strings.NewReader(url.Values{
			"code":          {req.Code},
			"code_verifier": {req.CodeVerifier},
			"grant_type":    {"authorization_code"},
		}.Encode()))
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid token endpoint",
			})
		}
		if req.RefreshToken != "" {
			tokenRequest, err = http.NewRequest(http.MethodPost, req.TokenEndpoint, strings.NewReader(url.Values{
				"refresh_token": {req.RefreshToken},
				"grant_type":    {"refresh_token"},
			}.Encode()))
			if err != nil {
				util.RespondWithError(ctx, util.ErrorResponse{
					Code:    "E4001",
					Err:     err,
					Message: "invalid token endpoint",
				})
			}
		}
		tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokenRequest.SetBasicAuth(req.ClientID, req.ClientSecret)
		resp, err := http.DefaultClient.Do(tokenRequest)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid token endpoint",
			})
		}
		defer resp.Body.Close()
		io.CopyN(ctx.Writer, resp.Body, 2*1024*1024)
	} else if req.UserInfoEndpoint != "" {
		level.Info(logger).Log("msg", "userinfo endpoint", "userinfo_endpoint", req.UserInfoEndpoint)
		userInfoRequest, err := http.NewRequest(http.MethodGet, req.UserInfoEndpoint, nil)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid userinfo endpoint",
			})
		}
		userInfoRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", req.AccessToken))
		resp, err := http.DefaultClient.Do(userInfoRequest)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid userinfo endpoint",
			})
		}
		defer resp.Body.Close()
		io.CopyN(ctx.Writer, resp.Body, 2*1024*1024)
	} else if req.TokenEndpoint == "" && req.ClientID != "" {
		level.Info(logger).Log("msg", "get openid configuration by client id", "client_id", req.ClientID)
		oidcConfig, err := c.svc.GetOpenIDConfiguration(ctx, req.ClientID)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     err,
				Message: "invalid client id",
			})
		}
		ctx.JSON(http.StatusOK, oidcConfig)
		return
	}
}

func (c *OIDCController) GetApplicationByClientID(ctx *gin.Context) {
	clientID := ctx.Param("client_id")
	application, err := c.svc.GetApplicationAuthorizationByClientID(ctx, clientID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid client id",
		})
		return
	}
	ctx.JSON(http.StatusOK, application)
}
