package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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

type ArchVersions struct {
	X86_64   VersionInfo `json:"x86_64"`
	Aarch64  VersionInfo `json:"aarch64"`
}

type PlatformVersions struct {
	Windows ArchVersions `json:"windows"`
	MacOS   ArchVersions `json:"macos"`
	Linux   ArchVersions `json:"linux"`
}

type Config struct {
	mu       sync.RWMutex
	data     *PlatformVersions
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
	Edition      string           `json:"edition,omitempty"`
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

// Platform analytics structures
type PlatformStats struct {
	Platform        string
	Arch            string
	TotalChecks     int64
	UniqueClients   int64
	ChecksPerClient float64
}

type VersionStats struct {
	Platform        string
	Arch            string
	Version         string
	TotalChecks     int64
	UniqueClients   int64
	ChecksPerClient float64
}

type EditionStats struct {
	Edition         string
	TotalChecks     int64
	UniqueClients   int64
	ChecksPerClient float64
}

type WeeklyPlatformBucket struct {
	Week          string `json:"week"`
	Platform      string `json:"platform"`
	UniqueClients int64  `json:"uniqueClients"`
}

type PlatformAnalytics struct {
	Period          string
	PeriodLabel     string
	Stats           []PlatformStats
	EditionStats    []EditionStats
	VersionStats    []VersionStats
	GeneratedAt     string
	TotalClients    int64
	TotalChecks     int64
	WeeklyChartJSON string
}

// Feature analytics structures
type FeaturePopularity struct {
	FeatureName   string
	Category      string
	TotalUses     int64
	UniqueClients int64
	UsesPerClient float64
}

type FeatureTimeBucket struct {
	Bucket      string
	FeatureName string
	TotalUses   int64
}

type SessionMetrics struct {
	TotalSessions      int64
	UniqueClients      int64
	AvgSessionDuration float64
	SessionsPerClient  float64
}

type VersionFeatureStats struct {
	Dimension     string
	FeatureName   string
	TotalUses     int64
	UniqueClients int64
}

type FeatureAnalytics struct {
	Period             string
	PeriodLabel        string
	FeatureStats       []FeaturePopularity
	TimeBucketsJSON    string
	TimeGranularity    string
	Sessions           SessionMetrics
	VersionBreakdown   []VersionFeatureStats
	OSBreakdown        []VersionFeatureStats
	CountryBreakdown   []VersionFeatureStats
	GeneratedAt        string
	TotalUses          int64
	TotalUniqueClients int64
}

//go:embed templates/*.html
var templateFS embed.FS

// Known valid features - whitelist
var knownFeatures = map[string]bool{
	// File
	"file_new":              true,
	"file_open":             true,
	"file_save":             true,
	"file_export_pdf":       true,
	"file_export_svg":       true,
	"file_export_png":       true,
	"file_export_jpg":       true,
	"file_export_musicxml":  true,
	"file_import_musicxml":  true,
	"file_print":            true,
	"file_properties":       true,
	// Notation
	"notation_add_note":         true,
	"notation_add_rest":         true,
	"notation_add_tenor":        true,
	"notation_add_clef":         true,
	"measure_add":               true,
	"time_signature_change":     true,
	"notation_roll":             true,
	"notation_tie":              true,
	"notation_triplet":          true,
	"notation_accent":           true,
	"notation_dot":              true,
	"notation_copy":             true,
	"notation_cut":              true,
	"notation_drag_move":        true,
	"notation_drag_copy":        true,
	"notation_drag_to_library":  true,
	"notation_drag_from_library": true,
	"component_drag_move":       true,
	"component_resize":          true,
	"notation_squeeze":          true,
	"notation_unison":           true,
	"notation_beam":             true,
	"notation_ligature":         true,
	"notation_dynamics":         true,
	"notation_backstick":        true,
	"notation_both_strike":      true,
	"notation_shoulder_strike":  true,
	"notation_swap_hands":       true,
	"notation_barline_change":   true,
	"notation_volta":            true,
	"notation_paste":            true,
	// Grace Notes
	"grace_note_flam":      true,
	"grace_note_drag":      true,
	"grace_note_swiss":     true,
	"grace_note_rough":     true,
	"grace_note_open_drag": true,
	// Staff
	"staff_insert":         true,
	"staff_append":         true,
	"staff_delete":         true,
	"staff_clone":          true,
	"staff_second_time":    true,
	"staff_toggle_repeats": true,
	"staff_point_size":     true,
	// Part
	"part_insert": true,
	"part_append": true,
	// Tools
	"tools_beautify":     true,
	"tools_redistribute": true,
	"tools_align":        true,
	"tools_block_edit":   true,
	// Edit
	"edit_undo":   true,
	"edit_redo":   true,
	"edit_delete": true,
	// View
	"zoom_in":  true,
	"zoom_out": true,
	// Playback
	"playback_start": true,
}

var featureCategories = map[string]string{
	// File
	"file_new":             "File",
	"file_open":            "File",
	"file_save":            "File",
	"file_export_pdf":      "File",
	"file_export_svg":      "File",
	"file_export_png":      "File",
	"file_export_jpg":      "File",
	"file_export_musicxml": "File",
	"file_import_musicxml": "File",
	"file_print":           "File",
	"file_properties":      "File",
	// Notation
	"notation_add_note":        "Notation",
	"notation_add_rest":        "Notation",
	"notation_add_tenor":       "Notation",
	"notation_add_clef":        "Notation",
	"measure_add":              "Notation",
	"time_signature_change":    "Notation",
	"notation_roll":            "Notation",
	"notation_tie":             "Notation",
	"notation_triplet":         "Notation",
	"notation_accent":          "Notation",
	"notation_dot":             "Notation",
	"notation_copy":                "Notation",
	"notation_cut":                 "Notation",
	"notation_drag_move":           "Notation",
	"notation_drag_copy":           "Notation",
	"notation_drag_to_library":     "Notation",
	"notation_drag_from_library":   "Notation",
	"component_drag_move":          "Notation",
	"component_resize":             "Notation",
	"notation_squeeze":             "Notation",
	"notation_unison":          "Notation",
	"notation_beam":            "Notation",
	"notation_ligature":        "Notation",
	"notation_dynamics":        "Notation",
	"notation_backstick":       "Notation",
	"notation_both_strike":     "Notation",
	"notation_shoulder_strike": "Notation",
	"notation_swap_hands":      "Notation",
	"notation_barline_change":  "Notation",
	"notation_volta":           "Notation",
	"notation_paste":           "Notation",
	// Grace Notes
	"grace_note_flam":      "GraceNotes",
	"grace_note_drag":      "GraceNotes",
	"grace_note_swiss":     "GraceNotes",
	"grace_note_rough":     "GraceNotes",
	"grace_note_open_drag": "GraceNotes",
	// Staff
	"staff_insert":         "Staff",
	"staff_append":         "Staff",
	"staff_delete":         "Staff",
	"staff_clone":          "Staff",
	"staff_second_time":    "Staff",
	"staff_toggle_repeats": "Staff",
	"staff_point_size":     "Staff",
	// Part
	"part_insert": "Part",
	"part_append": "Part",
	// Tools
	"tools_beautify":     "Tools",
	"tools_redistribute": "Tools",
	"tools_align":        "Tools",
	"tools_block_edit":   "Tools",
	// Edit
	"edit_undo":   "Edit",
	"edit_redo":   "Edit",
	"edit_delete": "Edit",
	// View
	"zoom_in":  "View",
	"zoom_out": "View",
	// Playback
	"playback_start": "Playback",
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

var validEditions = map[string]bool{
	"community": true,
	"studio":    true,
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

	var platforms PlatformVersions
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&platforms); err != nil {
		return err
	}

	stat, err := os.Stat(c.filePath)
	if err != nil {
		return err
	}

	c.data = &platforms
	c.lastMod = stat.ModTime()
	log.Printf("Loaded platform versions: Windows(x64=%s,arm64=%s), macOS(x64=%s,arm64=%s), Linux(x64=%s,arm64=%s)",
		platforms.Windows.X86_64.Version, platforms.Windows.Aarch64.Version,
		platforms.MacOS.X86_64.Version, platforms.MacOS.Aarch64.Version,
		platforms.Linux.X86_64.Version, platforms.Linux.Aarch64.Version)
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

func (c *Config) Get() *PlatformVersions {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *Config) GetPlatformArch(platform, arch string) *VersionInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if c.data == nil {
		return nil
	}
	
	var archVersions *ArchVersions
	switch platform {
	case "windows":
		archVersions = &c.data.Windows
	case "macos":
		archVersions = &c.data.MacOS
	case "linux":
		archVersions = &c.data.Linux
	default:
		return nil
	}
	
	switch arch {
	case "x86_64":
		return &archVersions.X86_64
	case "aarch64":
		return &archVersions.Aarch64
	default:
		return nil
	}
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

	CREATE TABLE IF NOT EXISTS monthly_aggregates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		year_month TEXT NOT NULL,
		aggregation_level TEXT NOT NULL,
		platform TEXT,
		arch TEXT,
		version TEXT,
		unique_clients INTEGER NOT NULL,
		total_checks INTEGER NOT NULL,
		checks_per_client REAL NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		CHECK(aggregation_level IN ('overall', 'platform_arch', 'version'))
	);

	CREATE INDEX IF NOT EXISTS idx_monthly_year_month ON monthly_aggregates(year_month);
	CREATE INDEX IF NOT EXISTS idx_monthly_level ON monthly_aggregates(aggregation_level);
	CREATE INDEX IF NOT EXISTS idx_monthly_platform ON monthly_aggregates(platform);
	CREATE INDEX IF NOT EXISTS idx_monthly_version ON monthly_aggregates(version);

	CREATE TABLE IF NOT EXISTS feature_monthly_aggregates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		year_month TEXT NOT NULL,
		feature_name TEXT NOT NULL,
		app_version TEXT,
		os_family TEXT,
		country TEXT,
		total_uses INTEGER NOT NULL,
		unique_clients INTEGER NOT NULL,
		total_sessions INTEGER NOT NULL DEFAULT 0,
		avg_session_duration_sec REAL NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_feature_monthly_ym ON feature_monthly_aggregates(year_month);
	CREATE INDEX IF NOT EXISTS idx_feature_monthly_feature ON feature_monthly_aggregates(feature_name);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	log.Println("Database initialized successfully")

	// Migration: add edition column to all tables
	editionMigrations := []string{
		"ALTER TABLE version_checks ADD COLUMN edition TEXT NOT NULL DEFAULT 'studio'",
		"ALTER TABLE analytics_events ADD COLUMN edition TEXT NOT NULL DEFAULT 'studio'",
		"ALTER TABLE monthly_aggregates ADD COLUMN edition TEXT NOT NULL DEFAULT 'studio'",
		"ALTER TABLE feature_monthly_aggregates ADD COLUMN edition TEXT NOT NULL DEFAULT 'studio'",
	}
	for _, m := range editionMigrations {
		if _, err := db.Exec(m); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				return nil, fmt.Errorf("migration failed: %w", err)
			}
		}
	}

	// Add indexes on edition for raw tables
	editionIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_version_checks_edition ON version_checks(edition)",
		"CREATE INDEX IF NOT EXISTS idx_analytics_edition ON analytics_events(edition)",
	}
	for _, idx := range editionIndexes {
		if _, err := db.Exec(idx); err != nil {
			return nil, fmt.Errorf("index creation failed: %w", err)
		}
	}

	return db, nil
}

func validateClientID(clientID string) bool {
	// Must be 64 character hex string (SHA-256)
	matched, _ := regexp.MatchString("^[a-f0-9]{64}$", clientID)
	return matched
}

func normalizeEdition(edition string) string {
	edition = strings.ToLower(strings.TrimSpace(edition))
	if validEditions[edition] {
		return edition
	}
	return "studio"
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
		return fmt.Errorf("invalid session start timestamp: got %d, server now %d, diff %dms", batch.SessionStart, now, batch.SessionStart-now)
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
			return fmt.Errorf("invalid event timestamp at index %d: got %d, server now %d, diff %dms", i, event.Timestamp, now, event.Timestamp-now)
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

// Monthly aggregation functions
func runMonthlyAggregation(db *sql.DB) error {
	log.Println("Starting monthly aggregation job...")

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Count records before aggregation
	var beforeCount int64
	err = tx.QueryRow("SELECT COUNT(*) FROM version_checks WHERE timestamp < datetime('now', '-1 year')").Scan(&beforeCount)
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	if beforeCount == 0 {
		log.Println("No records older than 1 year to aggregate")
		return nil
	}

	log.Printf("Found %d records older than 1 year to aggregate", beforeCount)

	// Check which months have already been aggregated
	var existingMonths []string
	rows, err := tx.Query("SELECT DISTINCT year_month FROM monthly_aggregates ORDER BY year_month")
	if err != nil {
		return fmt.Errorf("failed to query existing aggregates: %w", err)
	}
	for rows.Next() {
		var month string
		if err := rows.Scan(&month); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan month: %w", err)
		}
		existingMonths = append(existingMonths, month)
	}
	rows.Close()

	// Aggregate overall monthly totals
	log.Println("Aggregating overall monthly totals...")
	overallQuery := `
		INSERT INTO monthly_aggregates (year_month, aggregation_level, edition, unique_clients, total_checks, checks_per_client)
		SELECT
			strftime('%Y-%m', timestamp) as year_month,
			'overall' as aggregation_level,
			edition,
			COUNT(DISTINCT client_id) as unique_clients,
			COUNT(*) as total_checks,
			CAST(COUNT(*) AS REAL) / COUNT(DISTINCT client_id) as checks_per_client
		FROM version_checks
		WHERE timestamp < datetime('now', '-1 year')
			AND client_id IS NOT NULL
			AND client_id != ''
			AND strftime('%Y-%m', timestamp) || '-' || edition NOT IN (
				SELECT year_month || '-' || edition FROM monthly_aggregates WHERE aggregation_level = 'overall'
			)
		GROUP BY strftime('%Y-%m', timestamp), edition`

	result, err := tx.Exec(overallQuery)
	if err != nil {
		return fmt.Errorf("failed to aggregate overall totals: %w", err)
	}
	overallRows, _ := result.RowsAffected()
	log.Printf("Aggregated %d overall monthly records", overallRows)

	// Aggregate platform/arch monthly totals
	log.Println("Aggregating platform/arch monthly totals...")
	platformQuery := `
		INSERT INTO monthly_aggregates (year_month, aggregation_level, platform, arch, edition, unique_clients, total_checks, checks_per_client)
		SELECT
			strftime('%Y-%m', timestamp) as year_month,
			'platform_arch' as aggregation_level,
			substr(app_version, 1, instr(app_version || '-', '-') - 1) as platform,
			substr(
				substr(app_version, instr(app_version, '-') + 1),
				1,
				instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
			) as arch,
			edition,
			COUNT(DISTINCT client_id) as unique_clients,
			COUNT(*) as total_checks,
			CAST(COUNT(*) AS REAL) / COUNT(DISTINCT client_id) as checks_per_client
		FROM version_checks
		WHERE timestamp < datetime('now', '-1 year')
			AND client_id IS NOT NULL
			AND client_id != ''
			AND strftime('%Y-%m', timestamp) || '-' ||
				substr(app_version, 1, instr(app_version || '-', '-') - 1) || '-' ||
				substr(
					substr(app_version, instr(app_version, '-') + 1),
					1,
					instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
				) || '-' || edition NOT IN (
					SELECT year_month || '-' || COALESCE(platform, '') || '-' || COALESCE(arch, '') || '-' || edition
					FROM monthly_aggregates
					WHERE aggregation_level = 'platform_arch'
				)
		GROUP BY strftime('%Y-%m', timestamp), platform, arch, edition`

	result, err = tx.Exec(platformQuery)
	if err != nil {
		return fmt.Errorf("failed to aggregate platform totals: %w", err)
	}
	platformRows, _ := result.RowsAffected()
	log.Printf("Aggregated %d platform/arch monthly records", platformRows)

	// Aggregate version monthly totals
	log.Println("Aggregating version monthly totals...")
	versionQuery := `
		INSERT INTO monthly_aggregates (year_month, aggregation_level, platform, arch, version, edition, unique_clients, total_checks, checks_per_client)
		SELECT
			strftime('%Y-%m', timestamp) as year_month,
			'version' as aggregation_level,
			substr(app_version, 1, instr(app_version || '-', '-') - 1) as platform,
			substr(
				substr(app_version, instr(app_version, '-') + 1),
				1,
				instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
			) as arch,
			substr(app_version,
				length(
					substr(app_version, 1, instr(app_version || '-', '-') - 1) || '-' ||
					substr(
						substr(app_version, instr(app_version, '-') + 1),
						1,
						instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
					) || '-'
				) + 1
			) as version,
			edition,
			COUNT(DISTINCT client_id) as unique_clients,
			COUNT(*) as total_checks,
			CAST(COUNT(*) AS REAL) / COUNT(DISTINCT client_id) as checks_per_client
		FROM version_checks
		WHERE timestamp < datetime('now', '-1 year')
			AND client_id IS NOT NULL
			AND client_id != ''
			AND app_version IS NOT NULL
			AND app_version != ''
		GROUP BY strftime('%Y-%m', timestamp), platform, arch, version, edition`

	result, err = tx.Exec(versionQuery)
	if err != nil {
		return fmt.Errorf("failed to aggregate version totals: %w", err)
	}
	versionRows, _ := result.RowsAffected()
	log.Printf("Aggregated %d version monthly records", versionRows)

	// Delete old detailed records from version_checks
	log.Println("Deleting old version_checks records...")
	deleteVersionChecks := "DELETE FROM version_checks WHERE timestamp < datetime('now', '-1 year')"
	result, err = tx.Exec(deleteVersionChecks)
	if err != nil {
		return fmt.Errorf("failed to delete old version_checks: %w", err)
	}
	deletedVersionChecks, _ := result.RowsAffected()
	log.Printf("Deleted %d old version_checks records", deletedVersionChecks)

	// Aggregate feature usage from analytics_events before deleting
	log.Println("Aggregating feature usage from analytics_events...")

	// Overall feature popularity by month
	featureOverallQuery := `
		INSERT INTO feature_monthly_aggregates (year_month, feature_name, edition, total_uses, unique_clients)
		SELECT
			strftime('%Y-%m', timestamp) as year_month,
			feature_name,
			edition,
			COUNT(*) as total_uses,
			COUNT(DISTINCT client_id) as unique_clients
		FROM analytics_events
		WHERE timestamp < datetime('now', '-1 year')
			AND event_type = 'feature_used'
			AND feature_name IS NOT NULL
			AND strftime('%Y-%m', timestamp) || '-' || edition NOT IN (
				SELECT DISTINCT year_month || '-' || edition FROM feature_monthly_aggregates
				WHERE app_version IS NULL AND os_family IS NULL AND country IS NULL
				AND feature_name != '__session_metrics__'
			)
		GROUP BY year_month, feature_name, edition`

	result, err = tx.Exec(featureOverallQuery)
	if err != nil {
		return fmt.Errorf("failed to aggregate feature usage: %w", err)
	}
	featureRows, _ := result.RowsAffected()
	log.Printf("Aggregated %d feature usage records", featureRows)

	// Per-version feature breakdown
	featureVersionQuery := `
		INSERT INTO feature_monthly_aggregates (year_month, feature_name, app_version, edition, total_uses, unique_clients)
		SELECT
			strftime('%Y-%m', timestamp) as year_month,
			feature_name,
			app_version,
			edition,
			COUNT(*) as total_uses,
			COUNT(DISTINCT client_id) as unique_clients
		FROM analytics_events
		WHERE timestamp < datetime('now', '-1 year')
			AND event_type = 'feature_used'
			AND feature_name IS NOT NULL
			AND app_version IS NOT NULL
		GROUP BY year_month, feature_name, app_version, edition`

	result, err = tx.Exec(featureVersionQuery)
	if err != nil {
		return fmt.Errorf("failed to aggregate feature version breakdown: %w", err)
	}
	featureVersionRows, _ := result.RowsAffected()
	log.Printf("Aggregated %d feature version breakdown records", featureVersionRows)

	// Session metrics by month
	sessionAggQuery := `
		INSERT INTO feature_monthly_aggregates (year_month, feature_name, edition, total_uses, unique_clients, total_sessions, avg_session_duration_sec)
		SELECT
			strftime('%Y-%m', s.timestamp) as year_month,
			'__session_metrics__' as feature_name,
			s.edition,
			0 as total_uses,
			COUNT(DISTINCT s.client_id) as unique_clients,
			COUNT(*) as total_sessions,
			COALESCE(AVG(
				CAST((julianday(e.timestamp) - julianday(s.timestamp)) * 86400 AS REAL)
			), 0) as avg_session_duration_sec
		FROM analytics_events s
		LEFT JOIN analytics_events e ON s.client_id = e.client_id
			AND s.session_start = e.session_start
			AND e.event_type = 'session_end'
		WHERE s.timestamp < datetime('now', '-1 year')
			AND s.event_type = 'session_start'
			AND strftime('%Y-%m', s.timestamp) || '-' || s.edition NOT IN (
				SELECT DISTINCT year_month || '-' || edition FROM feature_monthly_aggregates
				WHERE feature_name = '__session_metrics__'
			)
		GROUP BY year_month, s.edition`

	result, err = tx.Exec(sessionAggQuery)
	if err != nil {
		return fmt.Errorf("failed to aggregate session metrics: %w", err)
	}
	sessionAggRows, _ := result.RowsAffected()
	log.Printf("Aggregated %d session metric records", sessionAggRows)

	// Delete old detailed records from analytics_events
	log.Println("Deleting old analytics_events records...")
	deleteAnalytics := "DELETE FROM analytics_events WHERE timestamp < datetime('now', '-1 year')"
	result, err = tx.Exec(deleteAnalytics)
	if err != nil {
		return fmt.Errorf("failed to delete old analytics_events: %w", err)
	}
	deletedAnalytics, _ := result.RowsAffected()
	log.Printf("Deleted %d old analytics_events records", deletedAnalytics)

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Monthly aggregation completed successfully")

	// Run VACUUM to reclaim disk space (outside transaction)
	log.Println("Running VACUUM to reclaim disk space...")
	if _, err := db.Exec("VACUUM"); err != nil {
		log.Printf("Warning: VACUUM failed: %v", err)
	} else {
		log.Println("VACUUM completed successfully")
	}

	return nil
}

func scheduleAggregationJob(db *sql.DB) {
	log.Println("Monthly aggregation job scheduler started")

	go func() {
		// Run immediately on startup (will only aggregate if needed)
		if err := runMonthlyAggregation(db); err != nil {
			log.Printf("Error in initial aggregation: %v", err)
		}

		// Schedule daily at 2:00 AM UTC
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			now := time.Now().UTC()
			// Calculate time until next 2:00 AM UTC
			next2AM := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, time.UTC)
			if now.After(next2AM) {
				next2AM = next2AM.Add(24 * time.Hour)
			}
			sleepDuration := next2AM.Sub(now)

			log.Printf("Next aggregation scheduled for: %s (in %s)", next2AM.Format(time.RFC3339), sleepDuration)

			time.Sleep(sleepDuration)

			// Run aggregation
			if err := runMonthlyAggregation(db); err != nil {
				log.Printf("Error in scheduled aggregation: %v", err)
			}
		}
	}()
}

func getClientIP(r *http.Request) string {
	// Check CF-Connecting-IP first (set by Cloudflare)
	ip := r.Header.Get("CF-Connecting-IP")
	if ip != "" {
		return ip
	}

	// Check X-Real-IP header (set by nginx)
	ip = r.Header.Get("X-Real-IP")
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

func getClientCountry(r *http.Request) string {
	// CF-IPCountry contains ISO 3166-1 alpha-2 country code (e.g., "US", "GB")
	// Returns "XX" for unknown, "T1" for Tor
	return r.Header.Get("CF-IPCountry")
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

		// Get platform and architecture from query parameters
		platform := r.URL.Query().Get("platform")
		arch := r.URL.Query().Get("arch")
		
		// Validate platform
		if platform == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Missing platform parameter",
				Details: "Please specify platform: ?platform=windows, ?platform=macos, or ?platform=linux",
			})
			return
		}

		if platform != "windows" && platform != "macos" && platform != "linux" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Invalid platform",
				Details: "Platform must be: windows, macos, or linux",
			})
			return
		}

		// Validate architecture
		if arch == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Missing arch parameter",
				Details: "Please specify arch: ?arch=x86_64 or ?arch=aarch64",
			})
			return
		}

		if arch != "x86_64" && arch != "aarch64" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Invalid architecture",
				Details: "Architecture must be: x86_64 or aarch64",
			})
			return
		}

		// Extract client ID if provided
		clientID := r.Header.Get("X-Client-ID")
		clientIP := getClientIP(r)
		clientCountry := getClientCountry(r)
		userAgent := r.Header.Get("User-Agent")
		clientVersion := r.Header.Get("X-App-Version")
		clientEdition := normalizeEdition(r.Header.Get("X-App-Edition"))

		// Get platform and arch specific version
		versionInfo := config.GetPlatformArch(platform, arch)
		if versionInfo == nil {
			http.Error(w, "Version information not available", http.StatusInternalServerError)
			return
		}

		// Log version check
		if clientID != "" && validateClientID(clientID) {
			_, err := db.Exec(`INSERT INTO version_checks
				(client_id, ip_address, country, user_agent, app_version, edition)
				VALUES (?, ?, ?, ?, ?, ?)`,
				clientID, clientIP, clientCountry, userAgent, platform+"-"+arch+"-"+clientVersion, clientEdition)
			if err != nil {
				log.Printf("Error logging version check: %v", err)
			}
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
			log.Printf("Analytics JSON parse failure: %v", err)
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
			log.Printf("Batch rejected from client %s: %v", batch.ClientID, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "Invalid request data",
				Details: err.Error(),
			})
			return
		}

		// Get client country from Cloudflare header
		clientCountry := getClientCountry(r)

		// Normalize edition: prefer JSON body field, fall back to header
		edition := batch.Edition
		if edition == "" {
			edition = r.Header.Get("X-App-Edition")
		}
		edition = normalizeEdition(edition)

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
				 app_version, os_family, os_version, os_arch, country, session_start, edition)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				eventTime, batch.ClientID, event.EventType, event.FeatureName,
				string(metadataJSON), batch.AppVersion, batch.OS.Family,
				batch.OS.Version, batch.OS.Arch, clientCountry, sessionStart, edition)

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

		log.Printf("Received %d events from client %s (version %s, edition %s, %s %s)",
			len(batch.Events), batch.ClientID, batch.AppVersion, edition,
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
		platformVersions := config.Get()
		if platformVersions == nil {
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

	// Platform analytics dashboard endpoint
	http.HandleFunc("/platforms", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get period from query parameter (default: day)
		period := r.URL.Query().Get("period")
		if period == "" {
			period = "day"
		}

		// Validate period
		validPeriods := map[string]string{
			"hour":  "Last Hour",
			"day":   "Last 24 Hours",
			"week":  "Last 7 Days",
			"month": "Last 30 Days",
			"year":  "Last Year",
		}

		periodLabel, validPeriod := validPeriods[period]
		if !validPeriod {
			http.Error(w, "Invalid period. Use: hour, day, week, month, or year", http.StatusBadRequest)
			return
		}

		// Build time filter based on period
		var timeFilter string
		switch period {
		case "hour":
			timeFilter = "datetime('now', '-1 hour')"
		case "day":
			timeFilter = "datetime('now', '-1 day')"
		case "week":
			timeFilter = "datetime('now', '-7 days')"
		case "month":
			timeFilter = "datetime('now', '-30 days')"
		case "year":
			timeFilter = "datetime('now', '-365 days')"
		}

		// Query platform/arch stats
		platformQuery := fmt.Sprintf(`
			SELECT
				substr(app_version, 1, instr(app_version || '-', '-') - 1) as platform,
				substr(
					substr(app_version, instr(app_version, '-') + 1),
					1,
					instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
				) as arch,
				COUNT(*) as total_checks,
				COUNT(DISTINCT client_id) as unique_clients,
				CAST(COUNT(*) AS REAL) / COUNT(DISTINCT client_id) as checks_per_client
			FROM version_checks
			WHERE timestamp >= %s
				AND client_id IS NOT NULL
				AND client_id != ''
			GROUP BY platform, arch
			ORDER BY platform, arch
		`, timeFilter)

		rows, err := db.Query(platformQuery)
		if err != nil {
			log.Printf("Error querying platform stats: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var stats []PlatformStats

		for rows.Next() {
			var stat PlatformStats
			err := rows.Scan(
				&stat.Platform,
				&stat.Arch,
				&stat.TotalChecks,
				&stat.UniqueClients,
				&stat.ChecksPerClient,
			)
			if err != nil {
				log.Printf("Error scanning platform row: %v", err)
				continue
			}
			stats = append(stats, stat)
		}

		// Query global totals with proper deduplication
		var totalClients int64
		var totalChecks int64
		totalsQuery := fmt.Sprintf(`
			SELECT COUNT(DISTINCT client_id), COUNT(*)
			FROM version_checks
			WHERE timestamp >= %s
				AND client_id IS NOT NULL
				AND client_id != ''
		`, timeFilter)
		if err := db.QueryRow(totalsQuery).Scan(&totalClients, &totalChecks); err != nil {
			log.Printf("Error querying totals: %v", err)
		}

		// Query version stats
		versionQuery := fmt.Sprintf(`
			SELECT
				substr(app_version, 1, instr(app_version || '-', '-') - 1) as platform,
				substr(
					substr(app_version, instr(app_version, '-') + 1),
					1,
					instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
				) as arch,
				substr(app_version,
					length(
						substr(app_version, 1, instr(app_version || '-', '-') - 1) || '-' ||
						substr(
							substr(app_version, instr(app_version, '-') + 1),
							1,
							instr(substr(app_version, instr(app_version, '-') + 1) || '-', '-') - 1
						) || '-'
					) + 1
				) as version,
				COUNT(*) as total_checks,
				COUNT(DISTINCT client_id) as unique_clients,
				CAST(COUNT(*) AS REAL) / COUNT(DISTINCT client_id) as checks_per_client
			FROM version_checks
			WHERE timestamp >= %s
				AND client_id IS NOT NULL
				AND client_id != ''
				AND app_version LIKE '%%-%%-%%'
				AND app_version NOT LIKE '%%-'
			GROUP BY platform, arch, version
			HAVING version != ''
			ORDER BY version DESC, platform, arch
		`, timeFilter)

		versionRows, err := db.Query(versionQuery)
		if err != nil {
			log.Printf("Error querying version stats: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer versionRows.Close()

		var versionStats []VersionStats

		for versionRows.Next() {
			var stat VersionStats
			err := versionRows.Scan(
				&stat.Platform,
				&stat.Arch,
				&stat.Version,
				&stat.TotalChecks,
				&stat.UniqueClients,
				&stat.ChecksPerClient,
			)
			if err != nil {
				log.Printf("Error scanning version row: %v", err)
				continue
			}
			versionStats = append(versionStats, stat)
		}

		// Query weekly platform data for chart (fixed 12-week window)
		var weeklyChartJSON string
		weeklyQuery := `
			SELECT
				strftime('%Y-W%W', timestamp) as week,
				substr(app_version, 1, instr(app_version || '-', '-') - 1) as platform,
				COUNT(DISTINCT client_id) as unique_clients
			FROM version_checks
			WHERE timestamp >= datetime('now', '-84 days')
				AND client_id IS NOT NULL
				AND client_id != ''
				AND app_version LIKE '%-%-_%'
			GROUP BY week, platform
			ORDER BY week, platform
		`
		weeklyRows, err := db.Query(weeklyQuery)
		if err != nil {
			log.Printf("Error querying weekly platform data: %v", err)
		} else {
			defer weeklyRows.Close()
			var buckets []WeeklyPlatformBucket
			for weeklyRows.Next() {
				var b WeeklyPlatformBucket
				if err := weeklyRows.Scan(&b.Week, &b.Platform, &b.UniqueClients); err != nil {
					log.Printf("Error scanning weekly row: %v", err)
					continue
				}
				buckets = append(buckets, b)
			}
			if jsonBytes, err := json.Marshal(buckets); err == nil {
				weeklyChartJSON = string(jsonBytes)
			} else {
				log.Printf("Error marshaling weekly chart data: %v", err)
			}
		}

		// Query edition breakdown
		editionQuery := fmt.Sprintf(`
			SELECT
				edition,
				COUNT(*) as total_checks,
				COUNT(DISTINCT client_id) as unique_clients,
				CAST(COUNT(*) AS REAL) / COUNT(DISTINCT client_id) as checks_per_client
			FROM version_checks
			WHERE timestamp >= %s
				AND client_id IS NOT NULL
				AND client_id != ''
			GROUP BY edition
			ORDER BY edition
		`, timeFilter)

		editionRows, err := db.Query(editionQuery)
		if err != nil {
			log.Printf("Error querying edition stats: %v", err)
		}

		var editionStats []EditionStats
		if editionRows != nil {
			defer editionRows.Close()
			for editionRows.Next() {
				var stat EditionStats
				if err := editionRows.Scan(&stat.Edition, &stat.TotalChecks, &stat.UniqueClients, &stat.ChecksPerClient); err != nil {
					log.Printf("Error scanning edition row: %v", err)
					continue
				}
				editionStats = append(editionStats, stat)
			}
		}

		// Prepare template data
		data := PlatformAnalytics{
			Period:          period,
			PeriodLabel:     periodLabel,
			Stats:           stats,
			EditionStats:    editionStats,
			VersionStats:    versionStats,
			GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
			TotalClients:    totalClients,
			TotalChecks:     totalChecks,
			WeeklyChartJSON: weeklyChartJSON,
		}

		// Render template
		funcMap := template.FuncMap{
			"safeJS": func(s string) template.JS {
				return template.JS(s)
			},
		}
		tmpl, err := template.New("platforms.html").Funcs(funcMap).ParseFS(templateFS, "templates/platforms.html")
		if err != nil {
			log.Printf("Error parsing template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Error executing template: %v", err)
		}
	})

	// Feature analytics dashboard endpoint
	http.HandleFunc("/analytics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		period := r.URL.Query().Get("period")
		if period == "" {
			period = "day"
		}

		validPeriods := map[string]string{
			"hour":  "Last Hour",
			"day":   "Last 24 Hours",
			"week":  "Last 7 Days",
			"month": "Last 30 Days",
			"year":  "Last Year",
		}

		periodLabel, validPeriod := validPeriods[period]
		if !validPeriod {
			http.Error(w, "Invalid period. Use: hour, day, week, month, or year", http.StatusBadRequest)
			return
		}

		var timeFilter string
		switch period {
		case "hour":
			timeFilter = "datetime('now', '-1 hour')"
		case "day":
			timeFilter = "datetime('now', '-1 day')"
		case "week":
			timeFilter = "datetime('now', '-7 days')"
		case "month":
			timeFilter = "datetime('now', '-30 days')"
		case "year":
			timeFilter = "datetime('now', '-365 days')"
		}

		// Time bucketing format for Chart.js
		var timeBucketFormat string
		var timeGranularity string
		switch period {
		case "hour":
			timeBucketFormat = "strftime('%Y-%m-%d %H:', timestamp) || printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / 10) * 10)"
			timeGranularity = "10 min"
		case "day":
			timeBucketFormat = "strftime('%Y-%m-%d %H:00', timestamp)"
			timeGranularity = "hour"
		case "week", "month":
			timeBucketFormat = "strftime('%Y-%m-%d', timestamp)"
			timeGranularity = "day"
		case "year":
			timeBucketFormat = "strftime('%Y-%m', timestamp)"
			timeGranularity = "month"
		}

		// Query 1: Feature popularity
		featureQuery := fmt.Sprintf(`
			SELECT
				feature_name,
				COUNT(*) as total_uses,
				COUNT(DISTINCT client_id) as unique_clients,
				CAST(COUNT(*) AS REAL) / MAX(COUNT(DISTINCT client_id), 1) as uses_per_client
			FROM analytics_events
			WHERE event_type = 'feature_used'
				AND timestamp >= %s
				AND feature_name IS NOT NULL
			GROUP BY feature_name
			ORDER BY total_uses DESC
		`, timeFilter)

		rows, err := db.Query(featureQuery)
		if err != nil {
			log.Printf("Error querying feature stats: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var featureStats []FeaturePopularity
		var totalUses int64
		var totalUniqueClients int64

		clientSet := make(map[string]bool)

		for rows.Next() {
			var stat FeaturePopularity
			err := rows.Scan(&stat.FeatureName, &stat.TotalUses, &stat.UniqueClients, &stat.UsesPerClient)
			if err != nil {
				log.Printf("Error scanning feature row: %v", err)
				continue
			}
			stat.Category = featureCategories[stat.FeatureName]
			if stat.Category == "" {
				stat.Category = "Other"
			}
			featureStats = append(featureStats, stat)
			totalUses += stat.TotalUses
		}

		// Get total unique clients across all features
		clientQuery := fmt.Sprintf(`
			SELECT COUNT(DISTINCT client_id) FROM analytics_events
			WHERE event_type = 'feature_used' AND timestamp >= %s
		`, timeFilter)
		_ = db.QueryRow(clientQuery).Scan(&totalUniqueClients)
		_ = clientSet // suppress unused warning

		// Query 2: Usage over time (top features + bucketed)
		timeBucketQuery := fmt.Sprintf(`
			SELECT
				%s as bucket,
				feature_name,
				COUNT(*) as total_uses
			FROM analytics_events
			WHERE event_type = 'feature_used'
				AND timestamp >= %s
				AND feature_name IS NOT NULL
			GROUP BY bucket, feature_name
			ORDER BY bucket, total_uses DESC
		`, timeBucketFormat, timeFilter)

		timeRows, err := db.Query(timeBucketQuery)
		if err != nil {
			log.Printf("Error querying time buckets: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer timeRows.Close()

		var timeBuckets []FeatureTimeBucket
		for timeRows.Next() {
			var tb FeatureTimeBucket
			err := timeRows.Scan(&tb.Bucket, &tb.FeatureName, &tb.TotalUses)
			if err != nil {
				log.Printf("Error scanning time bucket row: %v", err)
				continue
			}
			timeBuckets = append(timeBuckets, tb)
		}

		timeBucketsJSON, _ := json.Marshal(timeBuckets)

		// Query 3: Session metrics
		var sessions SessionMetrics
		sessionQuery := fmt.Sprintf(`
			SELECT
				COUNT(*) as total_sessions,
				COUNT(DISTINCT client_id) as unique_clients
			FROM analytics_events
			WHERE event_type = 'session_start'
				AND timestamp >= %s
		`, timeFilter)
		_ = db.QueryRow(sessionQuery).Scan(&sessions.TotalSessions, &sessions.UniqueClients)

		if sessions.UniqueClients > 0 {
			sessions.SessionsPerClient = float64(sessions.TotalSessions) / float64(sessions.UniqueClients)
		}

		// Average session duration from paired start/end events
		durationQuery := fmt.Sprintf(`
			SELECT COALESCE(AVG(
				(julianday(e.timestamp) - julianday(s.timestamp)) * 86400
			), 0)
			FROM analytics_events s
			INNER JOIN analytics_events e ON s.client_id = e.client_id
				AND s.session_start = e.session_start
				AND e.event_type = 'session_end'
			WHERE s.event_type = 'session_start'
				AND s.timestamp >= %s
		`, timeFilter)
		_ = db.QueryRow(durationQuery).Scan(&sessions.AvgSessionDuration)

		// Query 4: Version breakdown
		versionBreakdownQuery := fmt.Sprintf(`
			SELECT
				app_version,
				feature_name,
				COUNT(*) as total_uses,
				COUNT(DISTINCT client_id) as unique_clients
			FROM analytics_events
			WHERE event_type = 'feature_used'
				AND timestamp >= %s
				AND app_version IS NOT NULL
				AND feature_name IS NOT NULL
			GROUP BY app_version, feature_name
			ORDER BY total_uses DESC
		`, timeFilter)

		vbRows, err := db.Query(versionBreakdownQuery)
		if err != nil {
			log.Printf("Error querying version breakdown: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer vbRows.Close()

		var versionBreakdown []VersionFeatureStats
		for vbRows.Next() {
			var s VersionFeatureStats
			err := vbRows.Scan(&s.Dimension, &s.FeatureName, &s.TotalUses, &s.UniqueClients)
			if err != nil {
				log.Printf("Error scanning version breakdown row: %v", err)
				continue
			}
			versionBreakdown = append(versionBreakdown, s)
		}

		// Query 5: OS breakdown
		osBreakdownQuery := fmt.Sprintf(`
			SELECT
				os_family,
				feature_name,
				COUNT(*) as total_uses,
				COUNT(DISTINCT client_id) as unique_clients
			FROM analytics_events
			WHERE event_type = 'feature_used'
				AND timestamp >= %s
				AND os_family IS NOT NULL
				AND feature_name IS NOT NULL
			GROUP BY os_family, feature_name
			ORDER BY total_uses DESC
		`, timeFilter)

		osRows, err := db.Query(osBreakdownQuery)
		if err != nil {
			log.Printf("Error querying OS breakdown: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer osRows.Close()

		var osBreakdown []VersionFeatureStats
		for osRows.Next() {
			var s VersionFeatureStats
			err := osRows.Scan(&s.Dimension, &s.FeatureName, &s.TotalUses, &s.UniqueClients)
			if err != nil {
				log.Printf("Error scanning OS breakdown row: %v", err)
				continue
			}
			osBreakdown = append(osBreakdown, s)
		}

		// Query 6: Country breakdown
		countryBreakdownQuery := fmt.Sprintf(`
			SELECT
				COALESCE(NULLIF(country, ''), 'Unknown') as country,
				feature_name,
				COUNT(*) as total_uses,
				COUNT(DISTINCT client_id) as unique_clients
			FROM analytics_events
			WHERE event_type = 'feature_used'
				AND timestamp >= %s
				AND feature_name IS NOT NULL
			GROUP BY country, feature_name
			ORDER BY total_uses DESC
		`, timeFilter)

		countryRows, err := db.Query(countryBreakdownQuery)
		if err != nil {
			log.Printf("Error querying country breakdown: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer countryRows.Close()

		var countryBreakdown []VersionFeatureStats
		for countryRows.Next() {
			var s VersionFeatureStats
			err := countryRows.Scan(&s.Dimension, &s.FeatureName, &s.TotalUses, &s.UniqueClients)
			if err != nil {
				log.Printf("Error scanning country breakdown row: %v", err)
				continue
			}
			countryBreakdown = append(countryBreakdown, s)
		}

		data := FeatureAnalytics{
			Period:             period,
			PeriodLabel:        periodLabel,
			FeatureStats:       featureStats,
			TimeBucketsJSON:    string(timeBucketsJSON),
			TimeGranularity:    timeGranularity,
			Sessions:           sessions,
			VersionBreakdown:   versionBreakdown,
			OSBreakdown:        osBreakdown,
			CountryBreakdown:   countryBreakdown,
			GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
			TotalUses:          totalUses,
			TotalUniqueClients: totalUniqueClients,
		}

		funcMap := template.FuncMap{
			"safeJS": func(s string) template.JS {
				return template.JS(s)
			},
		}

		tmpl, err := template.New("analytics.html").Funcs(funcMap).ParseFS(templateFS, "templates/analytics.html")
		if err != nil {
			log.Printf("Error parsing analytics template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Error executing analytics template: %v", err)
		}
	})

	// Start aggregation job
	scheduleAggregationJob(db)

	log.Println("Starting API server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
