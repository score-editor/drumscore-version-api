package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type VersionInfo struct {
	Version             string `json:"version"`
	Build               string `json:"build"`
	ReleaseDate         string `json:"releaseDate"`
	DownloadURL         string `json:"downloadUrl"`
	MinSupportedVersion string `json:"minSupportedVersion"`
	ReleaseNotes        string `json:"releaseNotes,omitempty"`
}

type Config struct {
	mu       sync.RWMutex
	data     *VersionInfo
	filePath string
	lastMod  time.Time
}

type OsInfo struct {
	Family  string `json:"family"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type AnalyticsEvent struct {
	Timestamp   int64                  `json:"timestamp"`
	EventType   string                 `json:"eventType"`
	FeatureName string                 `json:"featureName,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type AnalyticsBatch struct {
	ClientID     string           `json:"clientId"`
	AppVersion   string           `json:"appVersion"`
	OS           OsInfo           `json:"os"`
	SessionStart int64            `json:"sessionStart"`
	Events       []AnalyticsEvent `json:"events"`
}

type AnalyticsBatchResponse struct {
	Status         string `json:"status"`
	EventsReceived int    `json:"eventsReceived"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// Known valid features - whitelist
var knownFeatures = map[string]bool{
	"file_new":               true,
	"file_open":              true,
	"file_save":              true,
	"file_export_pdf":        true,
	"file_export_midi":       true,
	"file_print":             true,
	"notation_add_note":      true,
	"notation_delete_note":   true,
	"notation_edit_note":     true,
	"measure_add":            true,
	"measure_delete":         true,
	"tempo_change":           true,
	"time_signature_change":  true,
	"playback_start":         true,
	"playback_stop":          true,
	"playback_pause":         true,
	"zoom_in":                true,
	"zoom_out":               true,
	"view_fullscreen":        true,
	"metronome_toggle":       true,
	"tuner_open":             true,
}

var validOSFamilies = map[string]bool{
	"Windows": true,
	"macOS":   true,
	"Linux":   true,
}

var validArchs = map[string]bool{
	"x86_64":  true,
	"aarch64": true,
	"x86":     true,
}

var validEventTypes = map[string]bool{
	"feature_used":  true,
	"session_start": true,
	"session_end":   true,
	"error":         true,
}

func NewConfig(filePath string) *Config {
	return &Config{
		filePath: filePath,
	}
}

func (c *Config) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Open(c.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var info VersionInfo
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&info); err != nil {
		return err
	}

	stat, err := os.Stat(c.filePath)
	if err != nil {
		return err
	}

	c.data = &info
	c.lastMod = stat.ModTime()
	log.Printf("Loaded version config: %s (build: %s)", info.Version, info.Build)
	return nil
}

func (c *Config) CheckAndReload() error {
	stat, err := os.Stat(c.filePath)
	if err != nil {
		return err
	}

	c.mu.RLock()
	needsReload := stat.ModTime().After(c.lastMod)
	c.mu.RUnlock()

	if needsReload {
		log.Println("Config file modified, reloading...")
		return c.Load()
	}
	return nil
}

func (c *Config) Get() *VersionInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS version_checks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_id TEXT,
		ip_address TEXT,
		country TEXT,
		user_agent TEXT,
		app_version TEXT
	);

	CREATE TABLE IF NOT EXISTS analytics_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		client_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		feature_name TEXT,
		metadata TEXT,
		app_version TEXT,
		os_family TEXT,
		os_version TEXT,
		os_arch TEXT,
		country TEXT,
		session_start DATETIME,
		CHECK(event_type IN ('feature_used', 'session_start', 'session_end', 'error')),
		CHECK(os_family IN ('Windows', 'macOS', 'Linux')),
		CHECK(os_arch IN ('x86_64', 'aarch64', 'x86'))
	);

	CREATE INDEX IF NOT EXISTS idx_version_checks_client ON version_checks(client_id);
	CREATE INDEX IF NOT EXISTS idx_version_checks_timestamp ON version_checks(timestamp);
	CREATE INDEX IF NOT EXISTS idx_analytics_client ON analytics_events(client_id);
	CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_analytics_feature ON analytics_events(feature_name);
	CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics_events(event_type);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	log.Println("Database initialized successfully")
	return db, nil
}

func validateClientID(clientID string) bool {
	// Must be 64 character hex string (SHA-256)
	matched, _ := regexp.MatchString("^[a-f0-9]{64}$", clientID)
	return matched
}

func validateVersion(version string) bool {
	// Semantic versioning: major.minor.patch
	matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+$`, version)
	return matched
}

func validateBatch(batch AnalyticsBatch) error {
	// Event count validation
	if len(batch.Events) == 0 {
		return errors.New("no events in batch")
	}
	if len(batch.Events) > 1000 {
		return errors.New("batch too large, maximum 1000 events")
	}

	// Client ID format
	if !validateClientID(batch.ClientID) {
		return errors.New("invalid client ID format")
	}

	// App version format
	if !validateVersion(batch.AppVersion) {
		return errors.New("invalid app version format")
	}

	// OS validation
	if !validOSFamilies[batch.OS.Family] {
		return errors.New("invalid OS family")
	}
	if !validArchs[batch.OS.Arch] {
		return errors.New("invalid OS architecture")
	}

	// Session start timestamp
	now := time.Now().Unix() * 1000
	if batch.SessionStart > now || batch.SessionStart < (now-7*24*60*60*1000) {
		return errors.New("invalid session start timestamp")
	}

	// Validate each event
	for i, event := range batch.Events {
		if !validEventTypes[event.EventType] {
			return errors.New("invalid event type at index " + string(rune(i)))
		}

		// Feature name required for feature_used events
		if event.EventType == "feature_used" {
			if event.FeatureName == "" {
				return errors.New("feature name required for feature_used event")
			}
			if !knownFeatures[event.FeatureName] {
				return errors.New("unknown feature name: " + event.FeatureName)
			}
		}

		// Timestamp validation
		if event.Timestamp > now || event.Timestamp < (now-7*24*60*60*1000) {
			return errors.New("invalid event timestamp at index " + string(rune(i)))
		}
	}

	return nil
}

func validateSignature(body []byte, signature, secret string) bool {
	if secret == "" {
		// If no secret configured, skip validation (for initial deployment)
		return true
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func getClientIP(r *http.Request) string {
	// Check X-Real-IP header first (set by nginx)
	ip := r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Fallback to X-Forwarded-For
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take first IP in list
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fallback to RemoteAddr
	return r.RemoteAddr
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/app/config/version.json"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/app/data/analytics.db"
	}

	analyticsSecret := os.Getenv("ANALYTICS_SECRET")
	if analyticsSecret == "" {
		log.Println("WARNING: ANALYTICS_SECRET not set, signature validation disabled")
	}

	config := NewConfig(configPath)

	// Initial config load
	if err := config.Load(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := initDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Start background config reloader
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if err := config.CheckAndReload(); err != nil {
				log.Printf("Error reloading config: %v", err)
			}
		}
	}()

	// Version check endpoint
	http.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract client ID if provided
		clientID := r.Header.Get("X-Client-ID")
		clientIP := getClientIP(r)
		userAgent := r.Header.Get("User-Agent")

		// Log version check
		if clientID != "" && validateClientID(clientID) {
			_, err := db.Exec(`INSERT INTO version_checks 
				(client_id, ip_address, user_agent, app_version) 
				VALUES (?, ?, ?, ?)`,
				clientID, clientIP, userAgent, "unknown")
			if err != nil {
				log.Printf("Error logging version check: %v", err)
			}
		}

		versionInfo := config.Get()
		if versionInfo == nil {
			http.Error(w, "Version information not available", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")

		if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	})

	// Analytics batch endpoint
	http.HandleFunc("/api/analytics/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed"})
			return
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to read request body"})
			return
		}
		defer r.Body.Close()

		// Validate signature if secret is configured
		if analyticsSecret != "" {
			signature := r.Header.Get("X-Signature")
			if !validateSignature(body, signature, analyticsSecret) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid signature"})
				return
			}
		}

		// Parse batch
		var batch AnalyticsBatch
		if err := json.Unmarshal(body, &batch); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Invalid request format",
				Details: err.Error(),
			})
			return
		}

		// Validate batch
		if err := validateBatch(batch); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Invalid request data",
				Details: err.Error(),
			})
			return
		}

		// Get client IP for country lookup (simplified - just store IP for now)
		clientIP := getClientIP(r)

		// Store events in database
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}

		sessionStart := time.Unix(batch.SessionStart/1000, 0)

		for _, event := range batch.Events {
			eventTime := time.Unix(event.Timestamp/1000, 0)
			metadataJSON, _ := json.Marshal(event.Metadata)

			_, err := tx.Exec(`INSERT INTO analytics_events 
				(timestamp, client_id, event_type, feature_name, metadata, 
				 app_version, os_family, os_version, os_arch, country, session_start) 
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				eventTime, batch.ClientID, event.EventType, event.FeatureName,
				string(metadataJSON), batch.AppVersion, batch.OS.Family,
				batch.OS.Version, batch.OS.Arch, clientIP, sessionStart)

			if err != nil {
				tx.Rollback()
				log.Printf("Error inserting event: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
				return
			}
		}

		if err := tx.Commit(); err != nil {
			log.Printf("Error committing transaction: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}

		log.Printf("Received %d events from client %s (version %s, %s %s)",
			len(batch.Events), batch.ClientID, batch.AppVersion,
			batch.OS.Family, batch.OS.Version)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(AnalyticsBatchResponse{
			Status:         "accepted",
			EventsReceived: len(batch.Events),
		})
	})

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		versionInfo := config.Get()
		if versionInfo == nil {
			http.Error(w, "Unhealthy", http.StatusServiceUnavailable)
			return
		}

		// Check database connection
		if err := db.Ping(); err != nil {
			http.Error(w, "Database unhealthy", http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("Starting API server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
