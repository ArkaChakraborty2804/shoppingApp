package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
)

// --- Constants and Global Variables ---
const RoleSeller = "seller"

// This must be the same secret key as your auth service
var jwtKey = []byte("my_super_secret_signing_key_that_should_be_long_and_random")

// --- API Struct for Dependency Injection ---
type api struct {
	db *pgxpool.Pool
}

// --- Data Structures ---

// Claims struct to parse the JWT. It must include all fields from the auth service token.
type Claims struct {
	UserID   string `json:"user_id"` // IMPORTANT: We need the user's ID to fetch their products
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Product struct to match the database schema
type Product struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Price         float64   `json:"price"`
	StockQuantity int       `json:"stock_quantity"`
	SellerID      string    `json:"seller_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// --- HTTP Handler ---

// GetMyProductsHandler fetches all products belonging to the currently logged-in seller.
func (a *api) GetMyProductsHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the user's claims that were added to the context by the middleware.
	claims, ok := r.Context().Value("userClaims").(*Claims)
	if !ok {
		http.Error(w, "Could not retrieve user claims", http.StatusInternalServerError)
		return
	}

	// Query the database for all products where the seller_id matches the user's ID from the token.
	rows, err := a.db.Query(context.Background(),
		"SELECT id, name, description, price, stock_quantity, seller_id, created_at, updated_at FROM products WHERE seller_id=$1",
		claims.UserID)
	if err != nil {
		log.Printf("Database query error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the products.
	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.StockQuantity, &p.SellerID, &p.CreatedAt, &p.UpdatedAt); err != nil {
			log.Printf("Error scanning product row: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		products = append(products, p)
	}

	// If no products are found, return an empty list instead of an error.
	if products == nil {
		products = []Product{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

// --- Middleware ---

// jwtMiddleware validates the token and ensures the user is a seller.
func (a *api) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenStr := bearerToken[1]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		// SECURITY CHECK: Ensure the user has the 'seller' role.
		if claims.Role != RoleSeller {
			http.Error(w, "Forbidden: Seller role required", http.StatusForbidden)
			return
		}

		// Add the claims to the request context for the handler to use.
		ctx := context.WithValue(r.Context(), "userClaims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Main Function ---

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	dbpool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}
	defer dbpool.Close()

	apiHandler := &api{db: dbpool}

	r := mux.NewRouter()

	// Create a subrouter for protected routes that will use the middleware.
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(apiHandler.jwtMiddleware)

	// Register the handler for the GET request.
	protected.HandleFunc("/products", apiHandler.GetMyProductsHandler).Methods("GET")

	// This service will run on a different port internally than the auth service.
	port := "8083"
	srv := &http.Server{
		Handler:      r,
		Addr:         ":" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Printf("Products microservice starting on port %s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}