# Copyright 2026 Sven Victor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
RUN --mount=type=cache,id=go-pkg,target=/go/pkg --mount=type=cache,id=go-build-cache,target=/root/.cache/go-build go build -tags=ignore_console_static -ldflags "-s -w" -o ez-auth main.go

FROM alpine:3.22
WORKDIR /opt/ez-auth
COPY --from=backend /app/GeoLite2-City.mmdb /usr/local/share/ez-auth/GeoLite2-City.mmdb
COPY --from=backend /app/ez-auth /usr/local/bin/ez-auth

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ez-auth","--server.geoip_db_path=/usr/local/share/ez-auth/GeoLite2-City.mmdb"]