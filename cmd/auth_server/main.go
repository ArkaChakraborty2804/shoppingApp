package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Constants for user roles
const (
	RoleBuyer  = "buyer"
	RoleSeller = "seller"
)

// Use a secure key in a real application, loaded from environment variables.
var jwtKey = []byte("my_super_secret_signing_key_that_should_be_long_and_random")

// --- API Struct for Dependency Injection ---
type api struct {
	db *pgxpool.Pool
}

// --- Data Structures ---
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"` // ADDED
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
}

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"` // ADDED
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"` // ADDED
	Role     string `json:"role"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// --- HTTP Handlers (Methods on `api` struct) ---

func (a *api) SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// MODIFIED: Added email to validation
	if req.Username == "" || req.Password == "" || req.Role == "" || req.Email == "" {
		http.Error(w, "Username, email, password, and role are required", http.StatusBadRequest)
		return
	}
	if req.Role != RoleBuyer && req.Role != RoleSeller {
		http.Error(w, "Role must be either 'buyer' or 'seller'", http.StatusBadRequest)
		return
	}

	// Check if username already exists
	var existingUsername string
	err := a.db.QueryRow(context.Background(), "SELECT username FROM users WHERE username=$1", req.Username).Scan(&existingUsername)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Printf("Error checking for existing user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingUsername != "" {
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}

	// ADDED: Check if email already exists
	var existingEmail string
	err = a.db.QueryRow(context.Background(), "SELECT email FROM users WHERE email=$1", req.Email).Scan(&existingEmail)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Printf("Error checking for existing email: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingEmail != "" {
		http.Error(w, "Email already registered", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newUser := User{
		ID:           uuid.NewString(),
		Username:     req.Username,
		Email:        req.Email, // ADDED
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
	}

	// MODIFIED: Updated SQL INSERT statement
	_, err = a.db.Exec(context.Background(),
		"INSERT INTO users (id, username, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)",
		newUser.ID, newUser.Username, newUser.Email, newUser.PasswordHash, newUser.Role)
	if err != nil {
		log.Printf("Error inserting new user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("New user registered: %s, Role: %s", newUser.Username, newUser.Role)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func (a *api) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	// MODIFIED: Updated SQL SELECT and Scan
	err := a.db.QueryRow(context.Background(),
		"SELECT id, username, email, password_hash, role FROM users WHERE username=$1",
		req.Username).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			log.Printf("Database error on login: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		Email:    user.Email, // ADDED
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("User logged in: %s", user.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func (a *api) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*Claims)
	if !ok {
		http.Error(w, "Could not retrieve user claims from context", http.StatusInternalServerError)
		return
	}

	expiresAt := claims.ExpiresAt.Time
	_, err := a.db.Exec(context.Background(),
		"INSERT INTO token_deny_list (jti, expires_at) VALUES ($1, $2)",
		claims.ID, expiresAt)
	if err != nil {
		log.Printf("Error inserting token into deny list: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("User logged out: %s, Token ID: %s invalidated", claims.Username, claims.ID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

func (a *api) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*Claims)
	if !ok {
		http.Error(w, "Could not retrieve user claims from context", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// MODIFIED: Added email to response
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Token is valid",
		"username": claims.Username,
		"email":    claims.Email,
		"role":     claims.Role,
	})
}

// --- Middleware ---

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
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				http.Error(w, "Token has expired", http.StatusUnauthorized)
			} else {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			}
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		var exists bool
		err = a.db.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM token_deny_list WHERE jti=$1)", claims.ID).Scan(&exists)
		if err != nil {
			log.Printf("Error checking deny list: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if exists {
			log.Printf("Denied access for invalidated token ID: %s", claims.ID)
			http.Error(w, "Unauthorized: Token has been logged out", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userClaims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Background Task ---

func (a *api) cleanupDenyList() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		res, err := a.db.Exec(context.Background(), "DELETE FROM token_deny_list WHERE expires_at < NOW()")
		if err != nil {
			log.Printf("Error cleaning up deny list: %v", err)
			continue
		}
		cleanedCount := res.RowsAffected()
		if cleanedCount > 0 {
			log.Printf("Deny list cleanup complete. Removed %d expired token(s).", cleanedCount)
		}
	}
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

	go apiHandler.cleanupDenyList()

	r.HandleFunc("/signup", apiHandler.SignupHandler).Methods("POST")
	r.HandleFunc("/login", apiHandler.LoginHandler).Methods("POST")

	protected := r.PathPrefix("/").Subrouter()
	protected.Use(apiHandler.jwtMiddleware)
	protected.HandleFunc("/validate", apiHandler.ValidateHandler).Methods("GET")
	protected.HandleFunc("/logout", apiHandler.LogoutHandler).Methods("POST")

	port := "8082"
	srv := &http.Server{
		Handler:      r,
		Addr:         ":" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Printf("Auth microservice starting on port %s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}