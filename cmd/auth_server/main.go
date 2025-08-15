package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Constants for user roles
const (
	RoleBuyer  = "buyer"
	RoleSeller = "seller"
)

// Use a secure key in a real application, loaded from environment variables.
var jwtKey = []byte("my_super_secret_signing_key_that_should_be_long_and_random")

// --- Data Structures ---

// User struct holds user information.
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"` // The '-' tag prevents this field from being encoded in JSON responses.
	Role         string `json:"role"`
}

// Claims struct defines the data that will be stored in the JWT.
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// SignupRequest for parsing user registration JSON.
type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// LoginRequest for parsing user login JSON.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// --- In-Memory Storage ---
// In a production environment, replace these with a proper database (e.g., PostgreSQL, MySQL).

var userStore = make(map[string]User)
var userMutex = &sync.RWMutex{}

// The deny list stores the unique ID (JTI) and expiration time of logged-out tokens.
var (
	tokenDenyList = make(map[string]time.Time)
	denyListMutex = &sync.RWMutex{}
)

// --- HTTP Handlers ---

// SignupHandler handles new user registration.
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Input validation
	if req.Username == "" || req.Password == "" || req.Role == "" {
		http.Error(w, "Username, password, and role are required", http.StatusBadRequest)
		return
	}
	if req.Role != RoleBuyer && req.Role != RoleSeller {
		http.Error(w, "Role must be either 'buyer' or 'seller'", http.StatusBadRequest)
		return
	}

	userMutex.RLock()
	_, exists := userStore[req.Username]
	userMutex.RUnlock()
	if exists {
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}

	// Hash the password for secure storage
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newUser := User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
	}

	userMutex.Lock()
	userStore[req.Username] = newUser
	userMutex.Unlock()

	log.Printf("New user registered: %s, Role: %s", newUser.Username, newUser.Role)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// LoginHandler handles user authentication and issues a JWT.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userMutex.RLock()
	user, exists := userStore[req.Username]
	userMutex.RUnlock()
	if !exists {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			ID:        uuid.New().String(), // JTI (JWT ID) for logout tracking
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

// LogoutHandler invalidates a user's JWT by adding its ID to the deny list.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*Claims)
	if !ok {
		http.Error(w, "Could not retrieve user claims from context", http.StatusInternalServerError)
		return
	}

	expiresAt := claims.ExpiresAt.Time
	denyListMutex.Lock()
	tokenDenyList[claims.ID] = expiresAt
	denyListMutex.Unlock()

	log.Printf("User logged out: %s, Token ID: %s invalidated until %v", claims.Username, claims.ID, expiresAt.Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

// ValidateHandler is a protected endpoint to check if a token is valid.
func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("userClaims").(*Claims)
	if !ok {
		http.Error(w, "Could not retrieve user claims from context", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Token is valid",
		"username": claims.Username,
		"role":     claims.Role,
	})
}

// --- Middleware ---

// jwtMiddleware verifies the token for protected routes.
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format (must be 'Bearer <token>')", http.StatusUnauthorized)
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

		// Check if the token has been logged out (is on the deny list)
		denyListMutex.RLock()
		_, isDenied := tokenDenyList[claims.ID]
		denyListMutex.RUnlock()

		if isDenied {
			log.Printf("Denied access for invalidated token ID: %s", claims.ID)
			http.Error(w, "Unauthorized: Token has been logged out", http.StatusUnauthorized)
			return
		}

		// Pass the claims to the next handler via the request context
		ctx := context.WithValue(r.Context(), "userClaims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Background Task ---

// cleanupDenyList periodically removes expired tokens from the deny list.
func cleanupDenyList() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		denyListMutex.Lock()
		cleanedCount := 0
		for jti, expiresAt := range tokenDenyList {
			if now.After(expiresAt) {
				delete(tokenDenyList, jti)
				cleanedCount++
			}
		}
		denyListMutex.Unlock()
		if cleanedCount > 0 {
			log.Printf("Deny list cleanup complete. Removed %d expired token(s).", cleanedCount)
		}
	}
}

// --- Main Function ---

func main() {
	r := mux.NewRouter()

	// Start the background cleanup task for the deny list
	go cleanupDenyList()

	// Public routes (no middleware)
	r.HandleFunc("/signup", SignupHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")

	// Protected routes (require a valid JWT)
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(jwtMiddleware)
	protected.HandleFunc("/validate", ValidateHandler).Methods("GET")
	protected.HandleFunc("/logout", LogoutHandler).Methods("POST")

	// Server configuration
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
