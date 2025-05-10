FROM node:20-slim AS frontend

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
COPY web /app
WORKDIR /app

RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
RUN pnpm run build

FROM golang:1.24-alpine AS backend
COPY . /app
WORKDIR /app
COPY --from=frontend /app/dist /app/internal/server/static
RUN --mount=type=cache,id=homecache,target=/root/.cache/ if [ ! -f /root/.cache/GeoLite2-City.mmdb ];then \
    wget -O /root/.cache/GeoLite2-City.mmdb.gz -c "https://cdn.jsdelivr.net/npm/geolite2-city@1.0.10/GeoLite2-City.mmdb.gz" && \
    gunzip /root/.cache/GeoLite2-City.mmdb.gz && cp /root/.cache/GeoLite2-City.mmdb /app/GeoLite2-City.mmdb; \
    else \
       cp /root/.cache/GeoLite2-City.mmdb /app/GeoLite2-City.mmdb;  \
    fi
RUN --mount=type=cache,id=go-pkg,target=/go/pkg go mod download
RUN --mount=type=cache,id=go-pkg,target=/go/pkg --mount=type=cache,id=go-build-cache,target=/root/.cache/go-build go build -o ez-auth main.go

FROM alpine:3.22
WORKDIR /opt/ez-auth
COPY --from=backend /app/GeoLite2-City.mmdb /usr/local/share/ez-auth/GeoLite2-City.mmdb
COPY --from=backend /app/ez-auth /usr/local/bin/ez-auth

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ez-auth","--server.geoip_db_path=/usr/local/share/ez-auth/GeoLite2-City.mmdb"]