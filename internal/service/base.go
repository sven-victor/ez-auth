package service

import (
	"context"

	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	consoleservice "github.com/sven-victor/ez-console/pkg/service"
)

func init() {
	consoleservice.RegisterDefaultSettings(context.Background(), consolemodel.SettingSystemHomePage, "/ui/", "System home page")
	consoleservice.RegisterDefaultSettings(context.Background(), consolemodel.SettingSystemName, "EZ-Auth", "System name")
}
