# Multi-stage build for Falcn Production

# Build stage
FROM golang:1.25-alpine AS go-builder

# Install build dependencies for CGO (required by go-sqlite3)
RUN apk --no-cache add gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build API server and CLI binary
# CGO_ENABLED=1 is required for github.com/mattn/go-sqlite3
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags='-w -s -linkmode external -extldflags "-static"' \
    -a \
    -o falcn-api ./api/main.go && \
    CGO_ENABLED=1 GOOS=linux go build \
    -ldflags='-w -s -linkmode external -extldflags "-static"' \
    -a \
    -o falcn ./main.go

# Stage 2: Final runtime image
FROM alpine:3.19

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl \
    && update-ca-certificates

# Create app user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=go-builder /app/falcn-api /app/falcn-api
COPY --from=go-builder /app/falcn /app/falcn

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command - start the API server
CMD ["./falcn-api"]
