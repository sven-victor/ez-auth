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
