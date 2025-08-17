# ---- Build Stage for Auth Service ----
FROM golang:1.25.0-alpine3.21 AS builder

# Set the working directory
WORKDIR /app

# Copy and download dependencies first to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
# We copy everything, but only build the auth server
COPY . .

# Build only the auth-server application
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /auth-server ./cmd/auth_server

# ---- Final Stage for Auth Service ----
FROM alpine:latest

# Copy only the compiled binary from the builder stage
COPY --from=builder /auth-server /auth-server

# Expose the port for the auth service
EXPOSE 8082

# The command to run the application
CMD ["/auth-server"]