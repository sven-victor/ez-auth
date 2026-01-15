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
// It implements RESTful endpoints for various authentication and authorization features.
package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sven-victor/ez-console/server"
)

type EchoController struct {
}

func (c *EchoController) RegisterRoutes(ctx context.Context, router *gin.RouterGroup) {
	router.GET("/echo", c.Get)
}

// Get handles GET requests to the echo endpoint.
// @Summary Test API connectivity
// @Description Returns a simple OK message to test API connectivity
// @Tags Echo
// @Produce json
// @Success 200 {object} map[string]string "Returns a simple OK message"
// @Router /api/echo [get]
func (c *EchoController) Get(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func init() {
	server.RegisterControllers(func(ctx context.Context, svc server.Service) server.Controller {
		return &EchoController{}
	})
}
