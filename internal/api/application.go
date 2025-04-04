// Package api provides HTTP API controllers for the ez-auth service.
package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sven-victor/ez-console/pkg/middleware"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-console/pkg/util"
	"github.com/sven-victor/ez-console/server"

	"github.com/sven-victor/ez-auth/internal/model"
	"github.com/sven-victor/ez-auth/internal/service"
)

// ApplicationController handles application-related HTTP requests.
// It provides endpoints for application management and role management.
type ApplicationController struct {
	svc *service.ApplicationService
}

func (c *ApplicationController) RegisterRoutes(router *gin.RouterGroup) {
	apps := router.Group("/applications")
	{
		apps.GET("", middleware.RequirePermission("applications:view"), c.ListApplications)
		apps.POST("", middleware.RequirePermission("applications:create"), c.CreateApplication)
		apps.POST("/import", middleware.RequirePermission("applications:create"), c.ImportLDAPApplications)
		apps.GET("/:id", middleware.RequirePermission("applications:view"), c.GetApplication)
		apps.PUT("/:id", middleware.RequirePermission("applications:edit"), c.UpdateApplication)
		apps.DELETE("/:id", middleware.RequirePermission("applications:delete"), c.DeleteApplication)

		// Role management
		apps.POST("/:id/roles", middleware.RequirePermission("applications:roles:create"), c.CreateApplicationRole)
		apps.GET("/:id/roles", middleware.RequirePermission("applications:roles:view"), c.ListApplicationRoles)
		apps.DELETE("/:id/roles/:roleId", middleware.RequirePermission("applications:roles:delete"), c.DeleteApplicationRole)
		apps.PUT("/:id/users", middleware.RequirePermission("applications:roles:assign"), c.AssignUserRole)
		apps.DELETE("/:id/users/:userId", middleware.RequirePermission("applications:roles:assign"), c.UnassignUserRole)
		apps.GET("/:id/users", middleware.RequirePermission("applications:roles:view"), c.ListApplicationUsers)

		// Key management
		apps.POST("/:id/keys", middleware.RequirePermission("applications:keys:create"), c.CreateApplicationKey)
		apps.GET("/:id/keys", middleware.RequirePermission("applications:keys:view"), c.ListApplicationKeys)
		apps.DELETE("/:id/keys/:keyId", middleware.RequirePermission("applications:keys:delete"), c.DeleteApplicationKey)

		// Issuer management
		apps.POST("/:id/issuer-keys", middleware.RequirePermission("applications:issuer-keys:create"), c.CreateApplicationIssuerKey)
		apps.GET("/:id/issuer-keys", middleware.RequirePermission("applications:issuer-keys:view"), c.ListApplicationIssuerKeys)
		apps.DELETE("/:id/issuer-keys/:issuerKeyId", middleware.RequirePermission("applications:issuer-keys:delete"), c.DeleteApplicationIssuerKey)
	}
}

// ListApplications retrieves a paginated list of applications.
// @Summary List applications
// @Description Get a paginated list of applications with optional keyword filtering
// @Tags Applications
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(10)
// @Param keywords query string false "Search keywords"
// @Success 200 {object} util.Response{data=[]model.Application}
// @Failure 500 {object} util.ErrorResponse
// @Router /applications [get]
func (c *ApplicationController) ListApplications(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	keywords := ctx.DefaultQuery("keywords", "")
	status := ctx.DefaultQuery("status", "")

	apps, total, err := c.svc.ListApplications(ctx, keywords, status, page, pageSize)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to list applications",
		})
		return
	}

	ctx.JSON(http.StatusOK, util.PaginationResponse{
		Code:     "0",
		Data:     apps,
		Total:    total,
		Current:  page,
		PageSize: pageSize,
	})
}

// CreateApplication creates a new application.
// @Summary Create application
// @Description Create a new application with the provided information
// @Tags model.Application
// @Accept json
// @Produce json
// @Param application body model.Application true "Application creation request"
// @Success 201 {object} util.Response{data=model.Application}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications [post]
func (c *ApplicationController) CreateApplication(ctx *gin.Context) {
	var req model.Application

	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request body",
		})
		return
	}

	if err := c.svc.CreateApplication(ctx, &req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to create application",
		})
		return
	}
	util.RespondWithSuccess(ctx, http.StatusCreated, req)
}

// GetApplication retrieves a specific application by ID.
// @Summary Get application
// @Description Get detailed information about a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {object} util.Response{data=model.Application}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id} [get]
func (c *ApplicationController) GetApplication(ctx *gin.Context) {
	appID := ctx.Param("id")
	app, err := c.svc.GetApplication(ctx, appID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to get application",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, app)
}

type UpdateApplicationRequest struct {
	Name            string            `json:"name"`
	DisplayName     string            `json:"display_name"`
	DisplayNameI18n map[string]string `json:"display_name_i18n"`
	Description     string            `json:"description"`
	DescriptionI18n map[string]string `json:"description_i18n"`
	Icon            string            `json:"icon"`
	Status          string            `json:"status"`
	GrantTypes      []string          `json:"grant_types"`
	URI             string            `json:"uri"`
	RedirectUris    []string          `json:"redirect_uris"`
	Scopes          []string          `json:"scopes"`
	LDAPAttrs       *[]model.LDAPAttr `json:"ldap_attrs"`
}

// UpdateApplication updates an existing application.
// @Summary Update application
// @Description Update an existing application's information
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param application body UpdateApplicationRequest true "Application update request"
// @Success 200 {object} util.Response{data=model.Application}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id} [put]
func (c *ApplicationController) UpdateApplication(ctx *gin.Context) {
	appID := ctx.Param("id")
	var req UpdateApplicationRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request body",
		})
		return
	}

	if req.LDAPAttrs != nil {
		if len(*req.LDAPAttrs) == 0 {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     errors.New("LDAP attrs is required"),
				Message: "LDAP attrs is required",
			})
			return
		} else {
			if err := c.svc.UpdateApplicationEntry(ctx, appID, *req.LDAPAttrs); err != nil {
				util.RespondWithError(ctx, util.ErrorResponse{
					Code:    "E5001",
					Err:     err,
					Message: "failed to update application entry",
				})
				return
			}
		}
	}

	if err := c.svc.UpdateApplication(ctx, &model.Application{
		Base: consolemodel.Base{
			ResourceID: appID,
		},
		Name:            req.Name,
		DisplayName:     req.DisplayName,
		Description:     req.Description,
		Icon:            req.Icon,
		Status:          req.Status,
		URI:             req.URI,
		GrantTypes:      req.GrantTypes,
		RedirectUris:    req.RedirectUris,
		Scopes:          req.Scopes,
		DisplayNameI18n: req.DisplayNameI18n,
		DescriptionI18n: req.DescriptionI18n,
	}); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to update application",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, req)
}

// DeleteApplication deletes an application by ID.
// @Summary Delete application
// @Description Delete an application by its ID
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id} [delete]
func (c *ApplicationController) DeleteApplication(ctx *gin.Context) {
	appID := ctx.Param("id")

	if err := c.svc.DeleteApplication(ctx, appID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to delete application",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, nil)
}

// CreateApplicationRole creates a new role for an application.
// @Summary Create application role
// @Description Create a new role for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param role body model.ApplicationRole true "Role creation request"
// @Success 201 {object} util.Response{data=model.ApplicationRole}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/roles [post]
func (c *ApplicationController) CreateApplicationRole(ctx *gin.Context) {
	appID := ctx.Param("id")
	var role model.ApplicationRole
	if err := ctx.ShouldBindJSON(&role); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request body",
		})
		return
	}

	role.ApplicationID = appID
	if err := c.svc.CreateApplicationRole(ctx, &role); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to create application role",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusCreated, role)
}

// ListApplicationRoles retrieves all roles for an application.
// @Summary List application roles
// @Description Get all roles for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {array} util.Response{data=[]model.ApplicationRole}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/roles [get]
func (c *ApplicationController) ListApplicationRoles(ctx *gin.Context) {
	appID := ctx.Param("id")
	roles, err := c.svc.ListApplicationRoles(ctx, appID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to list application roles",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, roles)
}

// DeleteApplicationRole deletes a role for an application.
// @Summary Delete application role
// @Description Delete a role for a specific application
// @Tags Applications
// @Param id path string true "Application ID"
// @Param roleId path string true "Role ID"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/roles/{roleId} [delete]
func (c *ApplicationController) DeleteApplicationRole(ctx *gin.Context) {
	appID := ctx.Param("id")
	roleID := ctx.Param("roleId")

	if err := c.svc.DeleteApplicationRole(ctx, appID, roleID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to delete application role",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, nil)
}

type AssignUserRoleRequest struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

// AssignUserRole assigns a role to a user for an application.
// @Summary Assign user role
// @Description Assign a role to a user for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param request body AssignUserRoleRequest true "Assign user role request"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/users [post]
func (c *ApplicationController) AssignUserRole(ctx *gin.Context) {
	appID := ctx.Param("id")
	var req AssignUserRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request body",
		})
		return
	}
	if err := c.svc.AssignUserRole(ctx, appID, req.UserID, req.RoleID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to assign user role",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, nil)
}

// UnassignUserRole unassigns a role from a user for an application.
// @Summary Unassign user role
// @Description Unassign a role from a user for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param userId path string true "User ID"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/users/{userId} [delete]
func (c *ApplicationController) UnassignUserRole(ctx *gin.Context) {
	appID := ctx.Param("id")
	userID := ctx.Param("userId")

	if err := c.svc.UnassignUserRole(ctx, appID, userID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to unassign user role",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, nil)
}

// ListApplicationUsers retrieves all users for an application.
// @Summary List application users
// @Description Get all users for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {array} util.Response{data=[]model.User}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/users [get]
func (c *ApplicationController) ListApplicationUsers(ctx *gin.Context) {
	appID := ctx.Param("id")
	users, err := c.svc.ListApplicationUsers(ctx, appID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to list application users",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, users)
}

// ImportLDAPApplicationsRequest represents the request body for importing LDAP applications.
type ImportLDAPApplicationsRequest struct {
	ApplicationDN []string `json:"application_dn"`
}

// ImportLDAPApplications imports applications from LDAP.
// @Summary Import LDAP applications
// @Description Import applications from LDAP directory
// @Tags Applications
// @Accept json
// @Produce json
// @Param request body ImportLDAPApplicationsRequest true "LDAP applications import request"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/import [post]
func (c *ApplicationController) ImportLDAPApplications(ctx *gin.Context) {

	type ImportLDAPApplicationsRequest struct {
		ApplicationDN []string `json:"application_dn"`
	}
	var req ImportLDAPApplicationsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      err,
		})
		return
	}
	if len(req.ApplicationDN) == 0 {
		applications, err := c.svc.ImportLDAPApplications(ctx, req.ApplicationDN)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				HTTPCode: http.StatusInternalServerError,
				Code:     "E5001",
				Err:      err,
			})
			return
		}
		ctx.JSON(http.StatusOK, util.Response{
			Code: "0",
			Data: applications,
		})
	} else {
		err := c.svc.StartAudit(ctx, "", func(auditLog *consolemodel.AuditLog) error {
			auditLog.ActionName = "Import LDAP Applications"
			applications, err := c.svc.ImportLDAPApplications(ctx, req.ApplicationDN)
			if err != nil {
				util.RespondWithError(ctx, util.ErrorResponse{
					HTTPCode: http.StatusInternalServerError,
					Code:     "E5001",
					Err:      err,
				})
			}
			ctx.JSON(http.StatusOK, util.Response{
				Code: "0",
				Data: applications,
			})
			return nil
		})
		if err != nil {
			util.RespondWithError(ctx, err)
			return
		}
	}
}

type CreateApplicationKeyRequest struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// CreateApplicationKey creates a new key for an application.
// @Summary Create application key
// @Description Create a new key for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 201 {object} util.Response{data=gin.H{client_id=string, client_secret=string}}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/keys [post]
func (c *ApplicationController) CreateApplicationKey(ctx *gin.Context) {
	appID := ctx.Param("id")

	var req CreateApplicationKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      err,
		})
		return
	}

	err := c.svc.StartAudit(ctx, "", func(auditLog *consolemodel.AuditLog) error {
		auditLog.ActionName = "Create application key"
		key, err := c.svc.CreateApplicationKey(ctx, appID, req.Name, req.ExpiresAt)
		if err != nil {
			return err
		}

		clientSecret, err := key.ClientSecret.UnsafeString()
		if err != nil {
			return err
		}
		util.RespondWithSuccess(ctx, http.StatusCreated, gin.H{
			"client_id":     key.ClientID,
			"client_secret": clientSecret,
		})
		return nil
	})
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}
}

// ListApplicationKeys retrieves all keys for an application.
// @Summary List application keys
// @Description Get all keys for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {array} util.Response{data=[]model.ApplicationKey}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/keys [get]
func (c *ApplicationController) ListApplicationKeys(ctx *gin.Context) {
	appID := ctx.Param("id")
	keys, err := c.svc.ListApplicationKeys(ctx, appID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusInternalServerError,
			Code:     "E5001",
			Err:      err,
		})
		return
	}
	util.RespondWithSuccess(ctx, http.StatusOK, keys)
}

// DeleteApplicationKey deletes a key for an application.
// @Summary Delete application key
// @Description Delete a key for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param keyId path string true "Key ID"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/keys/{keyId} [delete]
func (c *ApplicationController) DeleteApplicationKey(ctx *gin.Context) {
	appID := ctx.Param("id")
	keyID := ctx.Param("keyId")

	if err := c.svc.DeleteApplicationKey(ctx, appID, keyID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusInternalServerError,
			Code:     "E5001",
			Err:      err,
		})
		return
	}
	util.RespondWithSuccess(ctx, http.StatusOK, nil)
}

type CreateApplicationIssuerKeyRequest struct {
	Name       string `json:"name" binding:"required"`
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"`
}

// CreateApplicationIssuerKey creates a new issuer key for an application.
// @Summary Create application issuer key
// @Description Create a new issuer key for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param request body CreateApplicationIssuerKeyRequest true "Create application issuer key request"
// @Success 201 {object} util.Response{data=gin.H{issuer_key_id=string}}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/issuer-keys [post]
func (c *ApplicationController) CreateApplicationIssuerKey(ctx *gin.Context) {
	appID := ctx.Param("id")

	var req CreateApplicationIssuerKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      err,
		})
		return
	}

	err := c.svc.StartAudit(ctx, "", func(auditLog *consolemodel.AuditLog) error {
		key, err := c.svc.CreateApplicationIssuerKey(ctx, appID, req.Name, req.Algorithm, req.PrivateKey)
		if err != nil {
			return err
		}
		key.PrivateKey.Reset()
		util.RespondWithSuccess(ctx, http.StatusCreated, key)
		return nil
	})
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}
}

// ListApplicationIssuerKeys retrieves all issuer keys for an application.
// @Summary List application issuer keys
// @Description Get all issuer keys for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {array} util.Response{data=[]model.ApplicationPrivateKey}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/issuer-keys [get]
func (c *ApplicationController) ListApplicationIssuerKeys(ctx *gin.Context) {
	appID := ctx.Param("id")
	keys, err := c.svc.ListApplicationIssuerKeys(ctx, appID)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusInternalServerError,
			Code:     "E5001",
			Err:      err,
		})
		return
	}
	util.RespondWithSuccess(ctx, http.StatusOK, keys)
}

// DeleteApplicationIssuerKey deletes an issuer key for an application.
// @Summary Delete application issuer key
// @Description Delete an issuer key for a specific application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param issuerKeyId path string true "Issuer Key ID"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /applications/{id}/issuer-keys/{issuerKeyId} [delete]
func (c *ApplicationController) DeleteApplicationIssuerKey(ctx *gin.Context) {
	appID := ctx.Param("id")
	issuerKeyID := ctx.Param("issuerKeyId")

	if err := c.svc.DeleteApplicationIssuerKey(ctx, appID, issuerKeyID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusInternalServerError,
			Code:     "E5001",
			Err:      err,
		})
		return
	}
	util.RespondWithSuccess(ctx, http.StatusOK, nil)
}

func init() {
	server.RegisterControllers(func(svc server.Service) server.Controller {
		return &ApplicationController{
			svc: service.NewApplicationService(svc),
		}
	})

	middleware.RegisterPermission("Application Management", "Manage application creation, editing, deletion, and role assignment", []consolemodel.Permission{
		{
			Code:        "applications:view",
			Name:        "View applications",
			Description: "View applications list and details",
		},
		{
			Code:        "applications:create",
			Name:        "Create applications",
			Description: "Create new applications",
		},
		{
			Code:        "applications:edit",
			Name:        "Edit applications",
			Description: "Edit existing applications",
		},
		{
			Code:        "applications:delete",
			Name:        "Delete applications",
			Description: "Delete applications",
		},
		{
			Code:        "applications:roles:view",
			Name:        "View application roles",
			Description: "View application roles",
		},
		{
			Code:        "applications:roles:create",
			Name:        "Create application roles",
			Description: "Create application roles",
		},
		{
			Code:        "applications:roles:delete",
			Name:        "Delete application roles",
			Description: "Delete application roles",
		},
		{
			Code:        "applications:roles:assign",
			Name:        "Assign application roles",
			Description: "Assign roles to users",
		},
		{
			Code:        "applications:keys:view",
			Name:        "View application keys",
			Description: "View application keys",
		},
		{
			Code:        "applications:keys:create",
			Name:        "Create application keys",
			Description: "Create new application keys",
		},
		{
			Code:        "applications:keys:delete",
			Name:        "Delete application keys",
			Description: "Delete application keys",
		},
		{
			Code:        "applications:issuer-keys:view",
			Name:        "View application issuer keys",
			Description: "View application issuer keys",
		},
		{
			Code:        "applications:issuer-keys:create",
			Name:        "Create application issuer keys",
			Description: "Create new application issuer keys",
		},
		{
			Code:        "applications:issuer-keys:delete",
			Name:        "Delete application issuer keys",
			Description: "Delete application issuer keys",
		},
	})
}
