# ---- Build Stage for Products Service ----
FROM golang:1.25.0-alpine3.21 AS builder

# Set the working directory
WORKDIR /app

# Copy and download dependencies first to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
# We copy everything, but only build the products server
COPY . .

# Build only the products-server application
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /products-server ./cmd/products_server

# ---- Final Stage for Products Service ----
FROM alpine:latest

# Copy only the compiled binary from the builder stage
COPY --from=builder /products-server /products-server

# Expose the port for the products service
EXPOSE 8083

# The command to run the application
CMD ["/products-server"]