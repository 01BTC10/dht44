# Multi-stage build:
#   1. Node builds the React/Vite frontend.
#   2. nginx:alpine serves the bundle behind TLS.
# Run from the repo root: `docker compose -f deploy/docker-compose.yml build`.

# ---- build stage ----
FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- serve stage ----
FROM nginx:1.27-alpine
RUN rm -f /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY deploy/nginx/nginx.conf /etc/nginx/conf.d/dht44.conf
EXPOSE 80 443
