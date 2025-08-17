# ---- Build Stage ----
# Use the official Go image to build the application
FROM golang:1.25.0-alpine3.21 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application, disabling CGO for a static binary
# We target the specific main.go file in your cmd directory
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /auth-server ./cmd/auth_server

# ---- Final Stage ----
# Use a minimal base image for the final container
FROM alpine:latest

# Copy only the compiled binary from the builder stage
COPY --from=builder /auth-server /auth-server

# Expose the port the app runs on
EXPOSE 8082

# The command to run the application
CMD ["/auth-server"]