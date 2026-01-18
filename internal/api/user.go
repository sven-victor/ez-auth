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
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/sven-victor/ez-auth/internal/model"
	"github.com/sven-victor/ez-auth/internal/service"
	"github.com/sven-victor/ez-console/pkg/middleware"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	"github.com/sven-victor/ez-console/pkg/util"
	"github.com/sven-victor/ez-console/server"
)

// UserController handles user-related HTTP requests.
// It provides endpoints for user management including CRUD operations and password management.
type UserController struct {
	svc *service.UserService
}

func (c *UserController) RegisterRoutes(ctx context.Context, router *gin.RouterGroup) {
	users := router.Group("/users")
	{
		users.GET("", middleware.RequirePermission("authorization:user:list"), c.ListUsers)
		users.POST("", middleware.RequirePermission("authorization:user:create"), c.CreateUser)
		users.GET("/:id", middleware.RequirePermission("authorization:user:view"), c.GetUser)
		users.PUT("/:id", middleware.RequirePermission("authorization:user:update"), c.UpdateUser)
		users.DELETE("/:id", middleware.RequirePermission("authorization:user:delete"), c.DeleteUser)
		users.GET("/:id/applications", middleware.RequirePermission("authorization:user:view"), c.GetUserApplications)
		users.GET("/my-self/applications", c.GetMySelfApplications)
		users.GET("/:id/assignable-applications", middleware.RequirePermission("authorization:user:view"), c.GetUserAssignableApplications)
		users.POST("/:id/reset-password", middleware.RequirePermission("authorization:user:reset-password"), c.ResetPassword)
		users.POST("/import", middleware.RequirePermission("authorization:user:create"), c.ImportLDAPUsers)
		users.POST("/:id/restore", middleware.RequirePermission("authorization:user:update"), c.RestoreUser)
		users.GET("/ldap-users", middleware.RequirePermission("authorization:user:view"), c.GetLdapUsers)
	}
}

// ListUsers retrieves a paginated list of users with optional filtering.
// @Summary List users
// @Description Get a paginated list of users with optional filtering by username, email, and status
// @Tags Users
// @Accept json
// @Produce json
// @Param current query int false "Current page number" default(1)
// @Param page_size query int false "Number of items per page" default(10)
// @Param username query string false "Filter by username"
// @Param email query string false "Filter by email"
// @Param status query string false "Filter by status"
// @Success 200 {object} util.PaginationResponse{data=[]consolemodel.User}
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users [get]
func (c *UserController) ListUsers(ctx *gin.Context) {
	// Parse query parameters
	current, _ := strconv.Atoi(ctx.DefaultQuery("current", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	keywords := ctx.Query("keywords")
	status := ctx.Query("status")
	source := ctx.Query("source")

	users, total, err := c.svc.ListUsers(ctx, keywords, status, current, pageSize, source)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "failed to get users",
		})
		return
	}

	util.RespondWithSuccessList(ctx, http.StatusOK, users, total, current, pageSize)
}

type CreateUserRequest struct {
	Username    string           `json:"username"`
	Password    string           `json:"password"`
	Email       string           `json:"email"`
	FullName    string           `json:"full_name"`
	MFAEnforced bool             `json:"mfa_enforced"`
	LDAPAttrs   []model.LDAPAttr `json:"ldap_attrs"`
	RoleIDs     []string         `json:"role_ids"`
	Phone       string           `json:"phone"`
	Avatar      string           `json:"avatar"`
}

// CreateUser creates a new user.
// @Summary Create user
// @Description Create a new user with the provided information
// @Tags Users
// @Accept json
// @Produce json
// @Param user body CreateUserRequest true "User creation request"
// @Success 201 {object} consolemodel.User
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users [post]
func (c *UserController) CreateUser(ctx *gin.Context) {
	var req CreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     err,
			Message: "invalid request body",
		})
		return
	}
	if len(req.LDAPAttrs) == 0 {
		if len(req.Username) == 0 {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     errors.New("username is required"),
				Message: "username is required",
			})
			return
		}
		if len(req.Email) == 0 {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     errors.New("email is required"),
				Message: "email is required",
			})
			return
		}
		if len(req.FullName) == 0 {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     errors.New("full_name is required"),
				Message: "full_name is required",
			})
		}
	}

	user := &consolemodel.User{
		Username:    req.Username,
		Password:    req.Password,
		Email:       req.Email,
		FullName:    req.FullName,
		Status:      "active",
		MFAEnforced: req.MFAEnforced,
		Phone:       req.Phone,
		Avatar:      req.Avatar,
	}

	if err := c.svc.CreateUser(ctx, user, req.RoleIDs, req.LDAPAttrs); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5002",
			Err:     err,
			Message: "failed to create user",
		})
		return
	}

	ctx.JSON(http.StatusCreated, user)
}

// GetUser retrieves a specific user by ID.
// @Summary Get user
// @Description Get detailed information about a specific user
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} util.Response{data=consolemodel.User}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users/{id} [get]
func (c *UserController) GetUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if userID == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     nil,
			Message: "user ID is required",
		})
		return
	}

	user, err := c.svc.GetUser(ctx, userID, service.WithSoftDeleted(true), service.WithRoles(true))
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5003",
			Err:     err,
			Message: "failed to get user",
		})
		return
	}

	util.RespondWithSuccess(ctx, http.StatusOK, user)
}

type UpdateUserRequest struct {
	LDAPAttrs *[]model.LDAPAttr `json:"ldap_attrs"`
	service.UpdateUserRequest
}

// UpdateUser updates an existing user's information.
// @Summary Update user
// @Description Update an existing user's information
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body UpdateUserRequest true "User update request"
// @Success 200 {object} util.Response{data=consolemodel.User}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users/{id} [put]
func (c *UserController) UpdateUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if userID == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     nil,
			Message: "user ID is required",
		})
		return
	}
	var req UpdateUserRequest

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
		}
	} else {
		if req.Email == "" || req.Source == "" {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     errors.New("field email and source is required"),
				Message: "field email and source is required",
			})
			return
		}
	}
	var user *model.User
	var err error
	if req.LDAPAttrs != nil {
		if len(*req.LDAPAttrs) == 0 {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E4001",
				Err:     errors.New("LDAP attrs is required"),
				Message: "LDAP attrs is required",
			})
			return
		}
		if err = c.svc.UpdateUserEntry(ctx, userID, *req.LDAPAttrs); err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E5004",
				Err:     err,
				Message: "failed to update user LDAP attrs",
			})
			return
		}
		user, err = c.svc.GetUser(ctx, userID, service.WithRoles(true))
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E5003",
				Err:     err,
				Message: "failed to get user",
			})
			return
		}
	} else {
		if err := c.svc.UpdateUser(ctx, userID, req.UpdateUserRequest); err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				Code:    "E5004",
				Err:     err,
				Message: "failed to update user",
			})
			return
		}

	}
	util.RespondWithSuccess(ctx, http.StatusOK, user)
}

// DeleteUser deletes a user by ID.
// @Summary Delete user
// @Description Delete a user by their ID
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 204 "No Content"
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users/{id} [delete]
func (c *UserController) DeleteUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if userID == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     nil,
			Message: "user ID is required",
		})
		return
	}

	if err := c.svc.DeleteUser(ctx, userID); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5005",
			Err:     err,
			Message: "failed to delete user",
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// ResetPassword resets a user's password.
// @Summary Reset password
// @Description Reset a user's password
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} util.Response{data=map[string]string{new_password=string}}
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users/{id}/reset-password [post]
func (c *UserController) ResetPassword(ctx *gin.Context) {
	userID := ctx.Param("id")
	if userID == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     nil,
			Message: "user ID is required",
		})
		return
	}
	newPassword := util.GenerateRandomPassword(12)
	err := c.svc.StartAudit(ctx, userID, func(auditLog *consolemodel.AuditLog) error {
		auditLog.Action = "users:password:reset"
		auditLog.ActionName = "Reset Password"
		auditLog.Details.Request = map[string]any{
			"user_id": userID,
		}
		sendEmail, err := c.svc.ResetPassword(ctx, userID, newPassword)
		if err != nil {
			return util.ErrorResponse{
				Code:    "E5006",
				Err:     err,
				Message: "failed to reset password",
			}
		}
		auditLog.ActionName = "Reset Password"

		if !sendEmail {
			util.RespondWithSuccess(ctx, 200, gin.H{"new_password": newPassword})
		} else {
			util.RespondWithSuccess(ctx, 200, gin.H{})
		}
		return nil
	})
	if err != nil {
		util.RespondWithError(ctx, err)
		return
	}
}

// ImportLDAPUsersRequest represents the request body for importing LDAP users.
type ImportLDAPUsersRequest struct {
	UserDN []string `json:"user_dn"`
}

// ImportLDAPUsers imports users from LDAP.
// @Summary Import LDAP users
// @Description Import users from LDAP directory
// @Tags Users
// @Accept json
// @Produce json
// @Param request body ImportLDAPUsersRequest true "LDAP users import request"
// @Success 200 {object} util.Response
// @Failure 400 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /api/users/import [post]
func (c *UserController) ImportLDAPUsers(ctx *gin.Context) {
	var req ImportLDAPUsersRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			HTTPCode: http.StatusBadRequest,
			Code:     "E4001",
			Err:      err,
		})
		return
	}
	if len(req.UserDN) == 0 {
		users, err := c.svc.ImportLDAPUsers(ctx, req.UserDN)
		if err != nil {
			util.RespondWithError(ctx, util.ErrorResponse{
				HTTPCode: http.StatusInternalServerError,
				Code:     "E5001",
				Err:      err,
			})
			return
		}
		util.RespondWithSuccess(ctx, http.StatusOK, users)
	} else {
		err := c.svc.StartAudit(ctx, "", func(auditLog *consolemodel.AuditLog) error {
			auditLog.Action = "users:import:ldap"
			auditLog.ActionName = "Import LDAP Users"
			auditLog.Details.Request = map[string]any{
				"user_dn": req.UserDN,
			}
			users, err := c.svc.ImportLDAPUsers(ctx, req.UserDN)
			if err != nil {
				return util.ErrorResponse{
					HTTPCode: http.StatusInternalServerError,
					Code:     "E5001",
					Err:      err,
				}
			}
			util.RespondWithSuccess(ctx, http.StatusOK, users)
			return nil
		})
		if err != nil {
			util.RespondWithError(ctx, err)
			return
		}
	}

}

func init() {
	server.RegisterControllers(func(ctx context.Context, svc server.Service) server.Controller {
		return &UserController{
			svc: service.NewUserService(svc),
		}
	})

}

func (c *UserController) RestoreUser(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code: "E4001",
			Err:  errors.New("User ID cannot be empty"),
		})
		return
	}
	err := c.svc.StartAudit(
		ctx,
		id,
		func(auditLog *consolemodel.AuditLog) error {
			auditLog.Action = "users:restore"
			auditLog.ActionName = "Restore User"
			auditLog.Details.Request = map[string]any{
				"user_id": id,
			}
			err := c.svc.RestoreUser(ctx, id)
			if err != nil {
				return err
			}
			util.RespondWithSuccess(ctx, http.StatusOK, gin.H{"message": "User restored successfully"})
			return nil
		},
	)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "Failed to restore user",
		})
	}
}

func (c *UserController) GetLdapUsers(ctx *gin.Context) {
	skipExisting := ctx.Query("skip_existing") == "true"
	users, err := c.svc.GetLdapUsers(ctx, skipExisting)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "Failed to get LDAP users",
		})
		return
	}
	util.RespondWithSuccess(ctx, http.StatusOK, users)
}

func (c *UserController) GetUserApplications(ctx *gin.Context) {
	// Get organization ID from context
	orgID := ctx.GetString("organization_id")
	if orgID == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     errors.New("organization ID required"),
			Message: "organization ID required",
		})
		return
	}

	id := ctx.Param("id")
	if id == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code: "E4001",
			Err:  errors.New("User ID cannot be empty"),
		})
		return
	}
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	keywords := ctx.DefaultQuery("keywords", "")
	status := ctx.DefaultQuery("status", "")

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}
	applications, total, err := c.svc.GetUserApplications(ctx, orgID, id, keywords, status, page, pageSize)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "Failed to get user applications",
		})
		return
	}
	util.RespondWithSuccessList(ctx, http.StatusOK, applications, total, page, pageSize)
}

func (c *UserController) GetMySelfApplications(ctx *gin.Context) {
	id := middleware.GetUserIDFromContext(ctx)
	if id == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code: "E4001",
			Err:  errors.New("User ID cannot be empty"),
		})
		return
	}
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	keywords := ctx.DefaultQuery("keywords", "")
	status := ctx.DefaultQuery("status", "")

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}
	applications, total, err := c.svc.GetUserApplications(ctx, "", id, keywords, status, page, pageSize)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "Failed to get user applications",
		})
		return
	}
	util.RespondWithSuccessList(ctx, http.StatusOK, applications, total, page, pageSize)
}

func (c *UserController) GetUserAssignableApplications(ctx *gin.Context) {
	// Get organization ID from context
	orgID := ctx.GetString("organization_id")
	if orgID == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E4001",
			Err:     errors.New("organization ID required"),
			Message: "organization ID required",
		})
		return
	}

	id := ctx.Param("id")
	if id == "" {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code: "E4001",
			Err:  errors.New("User ID cannot be empty"),
		})
		return
	}
	keywords := ctx.DefaultQuery("keywords", "")
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}
	applications, total, err := c.svc.GetUserAssignableApplications(ctx, orgID, id, keywords, page, pageSize)
	if err != nil {
		util.RespondWithError(ctx, util.ErrorResponse{
			Code:    "E5001",
			Err:     err,
			Message: "Failed to get user assignable applications",
		})
		return
	}
	util.RespondWithSuccessList(ctx, http.StatusOK, applications, total, page, pageSize)
}
