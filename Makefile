.DEFAULT_GOAL := build

GO ?= go
FIRST_GOPATH := $(firstword $(subst :, ,$(shell $(GO) env GOPATH)))

SWAG     ?= $(FIRST_GOPATH)/bin/swag


$(SWAG):
	go install github.com/swaggo/swag/cmd/swag@v1.16.4

docs: $(SWAG)
	$(SWAG) init -g main.go -o docs -pd

web/node_modules:
	cd web && pnpm install

internal/server/static: web/node_modules
	cd web && pnpm build
	cp -r web/dist/ internal/server/static

dist/server:
	go mod tidy
	go build -ldflags "-s -w" -o dist/server main.go

clean:
	rm -rf dist/server
	rm -rf internal/server/static

clean-all: clean
	rm -rf web/node_modules
	rm -rf docs

.PHONY: build
build:internal/server/static dist/server

	