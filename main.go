package main

import (
	_ "github.com/sven-victor/ez-auth/docs"
	_ "github.com/sven-victor/ez-auth/internal/api"
	server "github.com/sven-victor/ez-auth/internal/server"

	consoleserver "github.com/sven-victor/ez-console/server"
)

var rootCmd = consoleserver.NewCommandServer("ez-auth", "ez-auth", consoleserver.WithEngineOptions(server.RegisterStaticFiles))

func main() {
	rootCmd.Execute()
}
