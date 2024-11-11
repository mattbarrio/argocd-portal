// main.go
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
)

// Global vars
var (
	db           *sql.DB
	tmpl         *template.Template
	config       *Config
	store        *sessions.CookieStore
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
)

func init() {
	log.Printf("Initializing configs")
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found: %v", err)
	}

	config = &Config{
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		IssuerURL:    os.Getenv("OIDC_ISSUER_URL"),
	}

	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		log.Fatal("SESSION_KEY environment variable is required")
	}

	// Initialize the global store
	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 24, // 24 hours
		HttpOnly: true,
		Secure:   true, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	initDB()

	tmpl = template.Must(template.ParseFiles("templates/index.html"))
}

func initDB() {
	log.Printf("Initializing database")
	var err error
	db, err = sql.Open("sqlite3", "./deployments.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
		env TEXT NOT NULL,
        status TEXT NOT NULL);`

	if _, err = db.Exec(createTable); err != nil {
		log.Fatal(err)
	}
}

type Deployment struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Env    string `json:"env"`
}

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	IssuerURL    string
}

func validateConfig() error {
	if config.IssuerURL == "" {
		return fmt.Errorf("OIDC_ISSUER_URL is required")
	}
	if config.ClientID == "" {
		return fmt.Errorf("OIDC_CLIENT_ID is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("OIDC_CLIENT_SECRET is required")
	}
	if config.RedirectURL == "" {
		return fmt.Errorf("OIDC_REDIRECT_URL is required")
	}

	// Validate URL has proper scheme
	if !strings.HasPrefix(config.IssuerURL, "http://") && !strings.HasPrefix(config.IssuerURL, "https://") {
		return fmt.Errorf("OIDC_ISSUER_URL must start with http:// or https://")
	}

	return nil
}

func initOIDC() {

	if err := validateConfig(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		log.Fatalf("Failed to query provider %q: %v", config.IssuerURL, err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling home")
	deployments := []Deployment{}
	rows, err := db.Query("SELECT id, name, url, status, env FROM deployments")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.Name, &d.URL, &d.Status, &d.Env); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		deployments = append(deployments, d)
	}

	tmpl.Execute(w, deployments)
}

func createDeployment(w http.ResponseWriter, r *http.Request) {
	var d Deployment
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO deployments (name, url, status, env) VALUES (?, ?, ?, ?)",
		d.Name, d.URL, d.Status, d.Env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	d.ID = int(id)
	json.NewEncoder(w).Encode(d)
}

func getDeployment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var d Deployment
	err := db.QueryRow("SELECT id, name, url, status, env FROM deployments WHERE id = ?", id).
		Scan(&d.ID, &d.Name, &d.URL, &d.Status, &d.Env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(d)
}

func updateDeployment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var d Deployment
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE deployments SET name = ?, url = ?, status = ?, env = ? WHERE id = ?",
		d.Name, d.URL, d.Status, d.Env, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.ID, err = strconv.Atoi(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(d)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Clear session values
	session.Values["authenticated"] = false
	session.Values["email"] = ""
	session.Options.MaxAge = -1 // Delete cookie

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			state := generateState()
			log.Printf("Generated state: %s", state)

			session.Values["state"] = state
			err = session.Save(r, w)
			if err != nil {
				log.Printf("Failed to save session: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Redirect to login
			redirectURL := oauth2Config.AuthCodeURL(state)
			log.Printf("Redirecting to: %s", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Checking API key")
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Missing API key", http.StatusUnauthorized)
			return
		}

		// Get API key from environment
		expectedKey := os.Getenv("API_KEY")
		if expectedKey == "" {
			log.Fatal("API_KEY environment variable is required")
		}

		if apiKey != expectedKey {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling callback")
	ctx := r.Context()
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in token response", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	session.Values["authenticated"] = true
	session.Values["email"] = idToken.Subject
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func main() {
	log.Println("Server started")
	initOIDC()
	r := mux.NewRouter()

	r.HandleFunc("/callback", handleCallback).Methods("GET")

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(apiKeyMiddleware)

	api.HandleFunc("/deployments", createDeployment).Methods("POST")
	api.HandleFunc("/deployments/{id}", getDeployment).Methods("GET")
	api.HandleFunc("/deployments/{id}", updateDeployment).Methods("PUT")

	// Auth routes
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(authMiddleware)

	protected.HandleFunc("/logout", handleLogout).Methods("GET")

	// Web routes
	protected.HandleFunc("/", homeHandler).Methods("GET")

	// Serve static files
	protected.PathPrefix("/resources/").Handler(http.StripPrefix("/resources/", http.FileServer(http.Dir("resources"))))

	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), r))
}

func generateState() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}
