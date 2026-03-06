# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (separate layer for caching)
COPY package.json package-lock.json ./
RUN npm ci --frozen-lockfile

# Copy source and build
COPY . .

# VITE_API_URL defaults to empty string so API calls use relative paths.
# Override at build time: docker build --build-arg VITE_API_URL=/api .
ARG VITE_API_URL=
ENV VITE_API_URL=${VITE_API_URL}

RUN npm run build

# ── Stage 2: Serve ────────────────────────────────────────────────────────────
FROM nginx:1.27-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Install curl for health check
RUN apk add --no-cache curl

# Copy nginx config and built assets
COPY nginx.conf /etc/nginx/conf.d/falcn.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# Non-root: nginx writes temp files to /tmp/nginx
RUN mkdir -p /tmp/nginx && chown -R nginx:nginx /tmp/nginx /var/cache/nginx /var/log/nginx

# Switch to non-root user
USER nginx

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
