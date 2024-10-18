package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Define database connection (using pgx driver)
var db *sql.DB

// Connect to PostgreSQL
func init() {
	var err error
	connStr := "postgres://user:password@localhost/dbname?sslmode=disable" // Set your PostgreSQL credentials here
	db, err = sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}
}

// Main function
func main() {
	// The backend target service
	backendTarget := "http://localhost:5000" // Replace this with your backend URL
	targetURL, err := url.Parse(backendTarget)
	if err != nil {
		log.Fatal("Error parsing target URL:", err)
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Attach middleware to reverse proxy
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authenticateAndAuthorize(w, r, proxy)
	})

	// Start the reverse proxy server
	log.Println("Reverse proxy running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Middleware to authenticate and authorize requests
func authenticateAndAuthorize(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	// Get the API key from Authorization header
	apiKey := r.Header.Get("Authorization")
	if apiKey == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Validate the API key and authorize access
	userID, projectID, scope, err := validateAPIKey(apiKey)
	if err != nil || !checkProjectAccess(userID, projectID, scope) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Add custom headers for the backend service
	r.Header.Set("X-User-ID", fmt.Sprintf("%d", userID))
	r.Header.Set("X-Project-ID", fmt.Sprintf("%d", projectID))

	// Serve the request via reverse proxy
	proxy.ServeHTTP(w, r)
}

// Validate the API key against the PostgreSQL database
func validateAPIKey(apiKey string) (userID, projectID int, scope string, err error) {
	var scopeDB string
	err = db.QueryRow(`SELECT user_id, project_id, scope FROM user_project_access 
        JOIN users ON users.id = user_project_access.user_id WHERE api_key = $1`, apiKey).Scan(&userID, &projectID, &scopeDB)
	if err != nil {
		return 0, 0, "", err
	}
	return userID, projectID, scopeDB, nil
}

// Check if the user has the required access scope
func checkProjectAccess(userID, projectID int, scope string) bool {
	var accessScope string
	err := db.QueryRow(`SELECT scope FROM user_project_access WHERE user_id = $1 AND project_id = $2`, userID, projectID).Scan(&accessScope)
	if err != nil || accessScope != scope {
		return false
	}
	return true
}
