package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AhmadNeemani/test/internal/database"
	"github.com/AhmadNeemani/test/internal/database/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	DB *database.Queries
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	portString := os.Getenv("PORT")
	if portString == "" {
		log.Fatal("PORT environment variable is not set")
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable is not set")
	}

	jwtSecretString := os.Getenv("JWT_SECRET")
	if jwtSecretString == "" {
		log.Fatal("JWT_SECRET environment variable is not set. Please generate a strong key.")
	}
	auth.SetJWTSecret([]byte(jwtSecretString))

	conn, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Can't connect to database: %v", err)
	}
	defer conn.Close()

	dbQueries := database.New(conn)
	apiCfg := apiConfig{
		DB: dbQueries,
	}

	router := chi.NewRouter()

	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*", "Authorization"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	v1Router := chi.NewRouter()

	v1Router.Get("/healthz", handlerReadiness)
	v1Router.Get("/err", handlerErr)

	// Public routes
	v1Router.Post("/users", apiCfg.handlerCreateUser)
	v1Router.Post("/login", apiCfg.handlerUserLogin)
	v1Router.Post("/refresh_token", apiCfg.handlerRefreshToken)

	// Authenticated routes
	v1Router.Group(func(r chi.Router) {
		r.Use(apiCfg.middlewareAuth) // Apply authentication middleware to this group

		// User profile route (authenticated user can get their own details)
		r.Get("/users", apiCfg.handlerGetUser) // This handles /v1/users for the authenticated user's own profile

		// Admin/SuperAdmin only routes for user management
		r.Get("/users/all", apiCfg.handlerGetAllUsers)       // Get all users (filtered by role)
		r.Put("/users/{userID}", apiCfg.handlerUpdateUser)   // Update a specific user by ID
		r.Delete("/users/{userID}", apiCfg.handlerDeleteUser) // Delete a specific user by ID
	})

	router.Mount("/v1", v1Router)

	srv := &http.Server{
		Handler:      router,
		Addr:         ":" + portString,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server on port %s", portString)

	err = srv.ListenAndServe()
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
