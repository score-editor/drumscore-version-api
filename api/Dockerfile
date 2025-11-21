# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy go files
COPY main.go .

# Initialize go module
RUN go mod init version-api && \
    go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o api main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/api .

# Create config directory
RUN mkdir -p /app/config

# Run as non-root user
RUN addgroup -g 1000 apiuser && \
    adduser -D -u 1000 -G apiuser apiuser && \
    chown -R apiuser:apiuser /app

USER apiuser

EXPOSE 8080

CMD ["./api"]
