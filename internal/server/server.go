package server

import (
	"embed"
	"net/http"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	w "github.com/sven-victor/ez-utils/wrapper"

	"github.com/sven-victor/ez-console/server"
)

// embed static files
//
//go:embed static
var staticFs embed.FS

//go:embed static/index.html
var indexHtml []byte

func IndexHandler(c *gin.Context) {
	c.Writer.Header().Del("Last-Modified")
	c.Writer.Header().Del("Cache-Control")
	c.Data(http.StatusOK, "text/html", indexHtml)
	c.Abort()
}

func RegisterStaticFiles(engine *gin.Engine) {
	embedFs := w.M(static.EmbedFolder(staticFs, "static"))
	staticHandler := static.ServeFileSystem(embedFs)
	engine.GET("/ui/*filepath", server.CacheControl, static.Serve("/ui", staticHandler), IndexHandler)
	engine.HEAD("/ui/*filepath", server.CacheControl, static.Serve("/ui", staticHandler), IndexHandler)
	engine.Any("/logo.png", func(c *gin.Context) {
		c.FileFromFS("/logo.png", staticHandler)
	})
}
