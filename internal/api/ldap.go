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
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sven-victor/ez-auth/internal/model"
	clientsldap "github.com/sven-victor/ez-console/pkg/clients/ldap"
	"github.com/sven-victor/ez-console/pkg/middleware"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-console/pkg/util"
	"github.com/sven-victor/ez-console/server"
	"github.com/sven-victor/ez-utils/safe"
)

// LDAPController handles LDAP-related HTTP requests.
// It provides endpoints for LDAP configuration management and testing.
type LDAPController struct {
	svc server.Service
}

func NewLDAPController(svc server.Service) *LDAPController {
	return &LDAPController{
		svc: svc,
	}
}

func init() {
	server.RegisterControllers(func(ctx context.Context, svc server.Service) server.Controller {
		return NewLDAPController(svc)
	})
}

// RegisterRoutes registers all routes for the LDAPController.
// @Summary Register LDAP routes
// @Description Registers all LDAP Settings endpoints
// @Tags LDAP
// @Router /api/ldap [get]
func (c *LDAPController) RegisterRoutes(ctx context.Context, router *gin.RouterGroup) {
	ldap := router.Group("/ldap")
	ldap.GET("/settings", middleware.RequirePermission("system:settings:view"), c.GetLDAPSettings)
	ldap.POST("/settings", middleware.RequirePermission("system:settings:update"), c.UpdateLDAPSettings)
	ldap.POST("/test", c.TestLDAPConnection)
}

// GetLDAPSettings retrieves the current LDAP configuration.
// @Summary Get LDAP settings
// @Description Retrieves the current LDAP configuration settings
// @Tags LDAP
// @Accept json
// @Produce json
// @Success 200 {object} util.Response{data=model.LDAPSettings}
// @Failure 500 {object} util.ErrorResponse
// @Router /api/ldap/settings [get]
func (c *LDAPController) GetLDAPSettings(ctx *gin.Context) {
	settings, err := c.svc.GetLDAPSettings(ctx)
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}
	if settings.BindPassword != nil {
		settings.BindPassword.UpdateSecret(util.GenerateRandomPassword(128))
	}
	settings.ClientKey = nil

	applicationLDAPEnabled, err := c.svc.GetBoolSetting(ctx, model.SettingLDAPApplicationLDAPEnabled, false)
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}
	applicationBaseDN, err := c.svc.GetStringSetting(ctx, model.SettingLDAPApplicationBaseDN, "")
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}

	applicationFilter, err := c.svc.GetStringSetting(ctx, model.SettingLDAPApplicationFilter, "")
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}

	applicationObjectClass, err := c.svc.GetStringSetting(ctx, model.SettingLDAPApplicationObjectClass, "")
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, model.LDAPSettings{
		LDAPApplicationSettings: model.LDAPApplicationSettings{
			ApplicationBaseDN:      applicationBaseDN,
			ApplicationFilter:      applicationFilter,
			ApplicationObjectClass: applicationObjectClass,
			ApplicationLDAPEnabled: applicationLDAPEnabled,
		},
		Options: settings,
	})
}

// LDAPSettingsRequest represents the request body for updating LDAP settings.
type LDAPSettingsRequest struct {
	model.LDAPSettings
	BindPassword string `json:"bind_password"`
	ClientKey    string `json:"client_key"`
}

// UpdateLDAPSettings updates the LDAP configuration.
// @Summary Update LDAP settings
// @Description Updates the LDAP configuration settings
// @Tags LDAP
// @Accept json
// @Produce json
// @Param settings body LDAPSettingsRequest true "LDAP settings"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/ldap/settings [post]
func (c *LDAPController) UpdateLDAPSettings(ctx *gin.Context) {
	// parse request body
	var req LDAPSettingsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4002",
			Err:      err,
		})
		return
	}

	req.Options.BindPassword = nil
	req.Options.ClientKey = nil
	if req.BindPassword != "" && !strings.HasPrefix(req.BindPassword, "{CRYPT}") {
		req.Options.BindPassword = safe.NewEncryptedString(req.BindPassword, os.Getenv(safe.SecretEnvName))
	}
	if req.ClientKey != "" && !strings.HasPrefix(req.ClientKey, "{CRYPT}") {
		req.Options.ClientKey = safe.NewEncryptedString(req.ClientKey, os.Getenv(safe.SecretEnvName))
	}

	settingsMap := map[string]string{
		string(consolemodel.SettingLDAPEnabled):         strconv.FormatBool(req.Enabled),
		string(consolemodel.SettingLDAPServerURL):       req.ServerURL,
		string(consolemodel.SettingLDAPBindDN):          req.BindDN,
		string(consolemodel.SettingLDAPBaseDN):          req.BaseDN,
		string(consolemodel.SettingLDAPUserFilter):      req.UserFilter,
		string(consolemodel.SettingLDAPUserAttr):        req.UserAttr,
		string(consolemodel.SettingLDAPEmailAttr):       req.EmailAttr,
		string(consolemodel.SettingLDAPDisplayNameAttr): req.DisplayNameAttr,
		string(consolemodel.SettingLDAPDefaultRole):     req.DefaultRole,
		string(consolemodel.SettingLDAPStartTLS):        strconv.FormatBool(req.StartTLS),
		string(consolemodel.SettingLDAPCACert):          req.CACert,
		string(consolemodel.SettingLDAPClientCert):      req.ClientCert,
		string(consolemodel.SettingLDAPInsecure):        strconv.FormatBool(req.Insecure),
		string(model.SettingLDAPApplicationLDAPEnabled): strconv.FormatBool(req.ApplicationLDAPEnabled),
		string(model.SettingLDAPApplicationBaseDN):      req.ApplicationBaseDN,
		string(model.SettingLDAPApplicationFilter):      req.ApplicationFilter,
		string(model.SettingLDAPApplicationObjectClass): req.ApplicationObjectClass,
	}

	if req.Options.ClientKey != nil {
		settingsMap[string(consolemodel.SettingLDAPClientKey)] = req.Options.ClientKey.String()
	}

	if req.Options.BindPassword != nil {
		settingsMap[string(consolemodel.SettingLDAPBindPassword)] = req.Options.BindPassword.String()
	}

	// use StartAudit to refactor audit log recording
	err := c.svc.StartAudit(
		ctx,
		"",
		func(auditLog *consolemodel.AuditLog) error {
			auditLog.Action = "system:settings:update"
			auditLog.ActionName = "Update LDAP Settings"
			return c.svc.UpdateSettings(ctx, settingsMap)
		},
	)
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, gin.H{"message": "Update LDAP Settings Success"})

}

type LDAPTestRequest struct {
	Username     string `json:"username" binding:"required"`
	Password     string `json:"password" binding:"required"`
	BindPassword string `json:"bind_password"`
	clientsldap.Options
}

// TestLDAPConnection tests the LDAP connection with provided credentials.
// @Summary Test LDAP connection
// @Description Tests the LDAP connection with provided credentials
// @Tags LDAP
// @Accept json
// @Produce json
// @Param request body LDAPTestRequest true "LDAP test request"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/ldap/test [post]
func (c *LDAPController) TestLDAPConnection(ctx *gin.Context) {
	var req LDAPTestRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      err,
		})
		return
	}

	if req.BindPassword != "" {
		if strings.HasPrefix(req.BindPassword, "{CRYPT}") {
			settings, err := c.svc.GetLDAPSettings(ctx)
			if err != nil {
				util.RespondWithError(ctx, util.ErrorResponse{
					HTTPCode: http.StatusInternalServerError,
					Code:     "E5001",
					Err:      err,
				})
				return
			}
			req.Options.BindPassword = settings.BindPassword
		} else {
			req.Options.BindPassword = safe.NewEncryptedString(req.BindPassword, os.Getenv(safe.SecretEnvName))
		}
	}
	resp, err := c.svc.TestLDAPConnection(ctx, req.Options, req.Username, req.Password)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusInternalServerError,
			Code:     "E5001",
			Err:      err,
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, resp)
}
