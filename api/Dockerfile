# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build

# Copy go files and templates
COPY main.go .
COPY templates/ templates/

# Initialize go module and add dependencies
RUN go mod init version-api && \
    go get github.com/mattn/go-sqlite3 && \
    go mod tidy

# Build the application with CGO enabled for SQLite
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags="-w -s" -o api main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata sqlite-libs

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/api .

# Create directories
RUN mkdir -p /app/config /app/data

# Run as non-root user
RUN addgroup -g 1000 apiuser && \
    adduser -D -u 1000 -G apiuser apiuser && \
    chown -R apiuser:apiuser /app

USER apiuser

EXPOSE 8080

CMD ["./api"]
