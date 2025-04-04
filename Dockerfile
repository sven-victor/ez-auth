FROM node:20-slim AS frontend

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
COPY web /app
WORKDIR /app

RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
RUN pnpm run build

FROM golang:1.23-alpine AS backend
COPY . /app
WORKDIR /app
COPY --from=frontend /app/dist /app/internal/server/static

RUN --mount=type=cache,id=go-pkg,target=/go/pkg go mod download
RUN --mount=type=cache,id=go-pkg,target=/go/pkg --mount=type=cache,id=go-build-cache,target=/root/.cache/go-build go build -o ez-auth main.go

FROM alpine:3.22
WORKDIR /opt/ez-auth
COPY --from=backend /app/ez-auth /usr/local/bin/ez-auth

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ez-auth"]