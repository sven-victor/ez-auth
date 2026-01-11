package main

import (
	_ "github.com/sven-victor/ez-auth/docs"
	_ "github.com/sven-victor/ez-auth/internal/api"
	server "github.com/sven-victor/ez-auth/internal/server"

	consoleserver "github.com/sven-victor/ez-console/server"
)

var (
	VERSION = "1.0.0"
)

var rootCmd = consoleserver.NewCommandServer("ez-auth", VERSION, "ez-auth", consoleserver.WithEngineOptions(server.RegisterStaticFiles))

func main() {
	rootCmd.Execute()
}
