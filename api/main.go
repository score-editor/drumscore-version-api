package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// UAT build and link types
type UATBuild struct {
	ID        int64  `json:"id"`
	Version   string `json:"version"`
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	Filename  string `json:"filename"`
	FileSize  int64  `json:"fileSize"`
	CreatedAt string `json:"createdAt"`
}

type UATLink struct {
	ID         int64  `json:"id"`
	Token      string `json:"token"`
	IssuedTo   string `json:"issuedTo"`
	BuildID    int64  `json:"buildId"`
	Version    string `json:"version,omitempty"`
	Platform   string `json:"platform,omitempty"`
	Arch       string `json:"arch,omitempty"`
	MaxUses    int    `json:"maxUses"`
	UseCount   int    `json:"useCount"`
	ExpiresAt  string `json:"expiresAt"`
	Revoked    bool   `json:"revoked"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

type CreateUATLinkRequest struct {
	IssuedTo       string `json:"issuedTo"`
	Version        string `json:"version"`
	Platform       string `json:"platform"`
	Arch           string `json:"arch"`
	SharedFileID   int64  `json:"sharedFileId"`
	MaxUses        int    `json:"maxUses"`
	ExpiresInHours int    `json:"expiresInHours"`
}

type SharedFile struct {
	ID           int64  `json:"id"`
	Filename     string `json:"filename"`
	OriginalName string `json:"originalName"`
	FileSize     int64  `json:"fileSize"`
	Description  string `json:"description"`
	CreatedAt    string `json:"createdAt"`
}

type CreateUATLinkResponse struct {
	Token        string `json:"token"`
	DownloadLink string `json:"downloadLink"`
	IssuedTo     string `json:"issuedTo"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Arch         string `json:"arch"`
	MaxUses      int    `json:"maxUses"`
	ExpiresAt    string `json:"expiresAt"`
}

//go:embed templates/*.html
var templateFS embed.FS

// Release notes types and parser

type ReleaseItem struct {
	Text string
}

type ReleaseSection struct {
	Category string
	Items    []ReleaseItem
}

type ReleaseVersion struct {
	Version  string
	Subtitle string
	Sections []ReleaseSection
}

type ReleaseNotes struct {
	mu        sync.RWMutex
	versions  map[string][]ReleaseVersion // lang -> versions
	langFiles map[string]time.Time        // lang -> last mod time
	dir       string
}

type ReleasesPageData struct {
	Versions        []ReleaseVersion
	AllVersions     []string
	SelectedVersion string
	SelectedLang    string
	AvailableLangs  []string
	LangLabels      map[string]string
	Current         *ReleaseVersion
	GeneratedAt     string
}

var versionHeaderRe = regexp.MustCompile(`^\s*v(\d+\.\d+(?:\.\d+)?)\s*(.*)$`)
var numberedItemRe = regexp.MustCompile(`^\s*(\d+)\.\s+(.*)$`)

var langLabels = map[string]string{
	"en": "English",
	"fr": "Français",
	"de": "Deutsch",
}

func parseReleaseFile(data []byte) []ReleaseVersion {
	var versions []ReleaseVersion
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	var currentVersion *ReleaseVersion
	var currentSection *ReleaseSection
	var currentItem *ReleaseItem
	pastHeader := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if trimmed == "" {
			continue
		}

		// Skip title/separator at top of file
		if !pastHeader {
			if strings.HasPrefix(trimmed, "===") {
				pastHeader = true
				continue
			}
			if currentVersion == nil && !versionHeaderRe.MatchString(trimmed) {
				continue
			}
			pastHeader = true
		}

		// Check for version header
		if m := versionHeaderRe.FindStringSubmatch(trimmed); m != nil {
			// Save previous item
			if currentItem != nil && currentSection != nil {
				currentSection.Items = append(currentSection.Items, *currentItem)
				currentItem = nil
			}
			// Save previous section
			if currentSection != nil && currentVersion != nil {
				currentVersion.Sections = append(currentVersion.Sections, *currentSection)
				currentSection = nil
			}
			// Save previous version
			if currentVersion != nil {
				versions = append(versions, *currentVersion)
			}
			currentVersion = &ReleaseVersion{
				Version:  m[1],
				Subtitle: strings.TrimSpace(m[2]),
			}
			continue
		}

		// Check for category header (supports English, French, and German)
		categoryMap := map[string]string{
			"FEATURES":          "FEATURES",
			"FONCTIONNALITÉS":   "FEATURES",
			"FONCTIONNALITES":   "FEATURES",
			"FUNKTIONEN":        "FEATURES",
			"BUGS":              "BUGS",
			"CORRECTIONS":       "BUGS",
			"FEHLER":            "BUGS",
		}
		if cat, ok := categoryMap[trimmed]; ok {
			// Save previous item
			if currentItem != nil && currentSection != nil {
				currentSection.Items = append(currentSection.Items, *currentItem)
				currentItem = nil
			}
			// Save previous section
			if currentSection != nil && currentVersion != nil {
				currentVersion.Sections = append(currentVersion.Sections, *currentSection)
			}
			currentSection = &ReleaseSection{Category: cat}
			continue
		}

		// Check for numbered item
		if m := numberedItemRe.FindStringSubmatch(trimmed); m != nil {
			// Save previous item
			if currentItem != nil && currentSection != nil {
				currentSection.Items = append(currentSection.Items, *currentItem)
			}
			currentItem = &ReleaseItem{Text: m[2]}
			continue
		}

		// Continuation line — append to current item
		if currentItem != nil {
			currentItem.Text += " " + trimmed
		}
	}

	// Flush remaining
	if currentItem != nil && currentSection != nil {
		currentSection.Items = append(currentSection.Items, *currentItem)
	}
	if currentSection != nil && currentVersion != nil {
		currentVersion.Sections = append(currentVersion.Sections, *currentSection)
	}
	if currentVersion != nil {
		versions = append(versions, *currentVersion)
	}

	return versions
}

func loadReleaseNotes(dir string) *ReleaseNotes {
	rn := &ReleaseNotes{
		versions:  make(map[string][]ReleaseVersion),
		langFiles: make(map[string]time.Time),
		dir:       dir,
	}
	rn.reload()
	return rn
}

func (rn *ReleaseNotes) reload() {
	files, err := filepath.Glob(filepath.Join(rn.dir, "*.txt"))
	if err != nil {
		log.Printf("Error scanning release notes dir: %v", err)
		return
	}

	for _, f := range files {
		lang := strings.TrimSuffix(filepath.Base(f), ".txt")
		info, err := os.Stat(f)
		if err != nil {
			log.Printf("Error stat release notes file %s: %v", f, err)
			continue
		}

		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("Error reading release notes file %s: %v", f, err)
			continue
		}

		rn.mu.Lock()
		rn.versions[lang] = parseReleaseFile(data)
		rn.langFiles[lang] = info.ModTime()
		rn.mu.Unlock()

		log.Printf("Loaded release notes: %s (%d versions)", lang, len(rn.versions[lang]))
	}
}

func (rn *ReleaseNotes) CheckAndReload() {
	files, err := filepath.Glob(filepath.Join(rn.dir, "*.txt"))
	if err != nil {
		return
	}

	for _, f := range files {
		lang := strings.TrimSuffix(filepath.Base(f), ".txt")
		info, err := os.Stat(f)
		if err != nil {
			continue
		}

		rn.mu.RLock()
		lastMod, exists := rn.langFiles[lang]
		rn.mu.RUnlock()

		if !exists || info.ModTime().After(lastMod) {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			rn.mu.Lock()
			rn.versions[lang] = parseReleaseFile(data)
			rn.langFiles[lang] = info.ModTime()
			rn.mu.Unlock()
			log.Printf("Reloaded release notes: %s", lang)
		}
	}
}

func (rn *ReleaseNotes) GetVersions(lang string) []ReleaseVersion {
	rn.mu.RLock()
	defer rn.mu.RUnlock()
	if v, ok := rn.versions[lang]; ok {
		return v
	}
	return nil
}

func (rn *ReleaseNotes) AvailableLangs() []string {
	rn.mu.RLock()
	defer rn.mu.RUnlock()
	langs := make([]string, 0, len(rn.versions))
	for lang := range rn.versions {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	return langs
}

func detectLanguage(r *http.Request, available []string) string {
	// Query param override
	if lang := r.URL.Query().Get("lang"); lang != "" {
		for _, a := range available {
			if a == lang {
				return lang
			}
		}
	}

	// Parse Accept-Language header
	accept := r.Header.Get("Accept-Language")
	if accept == "" {
		return "en"
	}

	type langPref struct {
		lang string
		q    float64
	}

	var prefs []langPref
	for _, part := range strings.Split(accept, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag := part
		q := 1.0
		if idx := strings.Index(part, ";q="); idx != -1 {
			tag = part[:idx]
			if v, err := strconv.ParseFloat(part[idx+3:], 64); err == nil {
				q = v
			}
		}
		tag = strings.TrimSpace(tag)
		// Extract primary language tag (e.g. "fr-FR" -> "fr")
		if idx := strings.IndexByte(tag, '-'); idx != -1 {
			tag = tag[:idx]
		}
		prefs = append(prefs, langPref{lang: strings.ToLower(tag), q: q})
	}

	// Sort by quality descending
	sort.Slice(prefs, func(i, j int) bool {
		return prefs[i].q > prefs[j].q
	})

	// Match against available
	for _, p := range prefs {
		for _, a := range available {
			if a == p.lang {
				return a
			}
		}
	}

	return "en"
}

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

	CREATE TABLE IF NOT EXISTS uat_builds (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version TEXT NOT NULL,
		platform TEXT NOT NULL,
		arch TEXT NOT NULL,
		filename TEXT NOT NULL,
		file_size INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		CHECK(platform IN ('windows', 'macos', 'linux')),
		CHECK(arch IN ('x86_64', 'aarch64'))
	);

	CREATE TABLE IF NOT EXISTS uat_links (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token TEXT NOT NULL UNIQUE,
		issued_to TEXT NOT NULL,
		build_id INTEGER NOT NULL,
		max_uses INTEGER NOT NULL DEFAULT 3,
		use_count INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME,
		FOREIGN KEY (build_id) REFERENCES uat_builds(id)
	);

	CREATE INDEX IF NOT EXISTS idx_uat_links_token ON uat_links(token);
	CREATE INDEX IF NOT EXISTS idx_uat_links_expires ON uat_links(expires_at);
	CREATE INDEX IF NOT EXISTS idx_uat_builds_version ON uat_builds(version);

	CREATE TABLE IF NOT EXISTS shared_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		original_name TEXT NOT NULL,
		file_size INTEGER NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
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

	// Migration: add shared_file_id to uat_links
	if _, err := db.Exec("ALTER TABLE uat_links ADD COLUMN shared_file_id INTEGER"); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return nil, fmt.Errorf("migration failed: %w", err)
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

	// Session start timestamp (allow 5 minutes of clock skew for clients ahead of server)
	now := time.Now().Unix() * 1000
	clockSkewTolerance := int64(5 * 60 * 1000)
	if batch.SessionStart > now+clockSkewTolerance || batch.SessionStart < (now-7*24*60*60*1000) {
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

// UAT helper functions

func validateAdminAuth(r *http.Request, secret string) bool {
	if secret == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+secret
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func uatErrorPage(title, message string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Drum Score Editor - %s</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; color: #333; }
.container { text-align: center; padding: 2rem; max-width: 500px; }
h1 { color: #c0392b; font-size: 1.5rem; }
p { font-size: 1.1rem; line-height: 1.6; color: #666; }
</style>
</head>
<body>
<div class="container">
<h1>%s</h1>
<p>%s</p>
</div>
</body>
</html>`, title, title, message)
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

	adminSecret := os.Getenv("ADMIN_SECRET")
	if adminSecret == "" {
		log.Println("WARNING: ADMIN_SECRET not set, UAT admin endpoints disabled")
	}

	uatBuildsDir := os.Getenv("UAT_BUILDS_PATH")
	if uatBuildsDir == "" {
		uatBuildsDir = "/app/data/uat-builds"
	}
	if err := os.MkdirAll(uatBuildsDir, 0755); err != nil {
		log.Fatalf("Failed to create UAT builds directory: %v", err)
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

	// Load release notes
	releaseNotesPath := os.Getenv("RELEASE_NOTES_PATH")
	if releaseNotesPath == "" {
		releaseNotesPath = "/app/release-notes"
	}
	releaseNotes := loadReleaseNotes(releaseNotesPath)

	// Start background config reloader
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if err := config.CheckAndReload(); err != nil {
				log.Printf("Error reloading config: %v", err)
			}
			releaseNotes.CheckAndReload()
		}
	}()

	// Redirect root to main website
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "https://drumscore.scot", http.StatusFound)
	})

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

	// Release notes page
	http.HandleFunc("/releases", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		releaseNotes.CheckAndReload()

		availableLangs := releaseNotes.AvailableLangs()
		if len(availableLangs) == 0 {
			http.Error(w, "No release notes available", http.StatusNotFound)
			return
		}

		lang := detectLanguage(r, availableLangs)
		versions := releaseNotes.GetVersions(lang)
		if versions == nil {
			// Fall back to English
			lang = "en"
			versions = releaseNotes.GetVersions(lang)
		}
		if versions == nil {
			http.Error(w, "No release notes available", http.StatusNotFound)
			return
		}

		// Build version list
		allVersions := make([]string, len(versions))
		for i, v := range versions {
			allVersions[i] = v.Version
		}

		// Select version
		selectedVersion := r.URL.Query().Get("version")
		var current *ReleaseVersion
		if selectedVersion != "" {
			for i := range versions {
				if versions[i].Version == selectedVersion {
					current = &versions[i]
					break
				}
			}
		}
		if current == nil && len(versions) > 0 {
			current = &versions[0]
			selectedVersion = current.Version
		}

		data := ReleasesPageData{
			Versions:        versions,
			AllVersions:     allVersions,
			SelectedVersion: selectedVersion,
			SelectedLang:    lang,
			AvailableLangs:  availableLangs,
			LangLabels:      langLabels,
			Current:         current,
			GeneratedAt:     time.Now().UTC().Format("2006-01-02 15:04:05"),
		}

		funcMap := template.FuncMap{
			"lower": strings.ToLower,
		}
		tmpl, err := template.New("releases.html").Funcs(funcMap).ParseFS(templateFS, "templates/releases.html")
		if err != nil {
			log.Printf("Error parsing releases template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Error executing releases template: %v", err)
		}
	})

	// ========================================================================
	// UAT Build & Link Management Endpoints
	// ========================================================================

	// Upload a UAT build
	http.HandleFunc("/api/admin/uat-builds", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		switch r.Method {
		case http.MethodPost:
			// Parse multipart form (max 500MB)
			if err := r.ParseMultipartForm(500 << 20); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to parse upload", Details: err.Error()})
				return
			}

			version := r.FormValue("version")
			platform := r.FormValue("platform")
			arch := r.FormValue("arch")

			if version == "" || platform == "" || arch == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing required fields: version, platform, arch"})
				return
			}

			if !validateVersion(version) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid version format", Details: "Must be semantic version: X.Y.Z"})
				return
			}

			if platform != "windows" && platform != "macos" && platform != "linux" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid platform", Details: "Must be: windows, macos, or linux"})
				return
			}
			if arch != "x86_64" && arch != "aarch64" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid arch", Details: "Must be: x86_64 or aarch64"})
				return
			}

			file, header, err := r.FormFile("file")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing file"})
				return
			}
			defer file.Close()

			// Store file as version-platform-arch-originalname
			safeFilename := fmt.Sprintf("%s-%s-%s-%s", version, platform, arch, filepath.Base(header.Filename))
			destPath := filepath.Join(uatBuildsDir, safeFilename)

			out, err := os.Create(destPath)
			if err != nil {
				log.Printf("Error creating UAT build file: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to store file"})
				return
			}
			defer out.Close()

			written, err := io.Copy(out, file)
			if err != nil {
				os.Remove(destPath)
				log.Printf("Error writing UAT build file: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to write file"})
				return
			}

			result, err := db.Exec(`INSERT INTO uat_builds (version, platform, arch, filename, file_size) VALUES (?, ?, ?, ?, ?)`,
				version, platform, arch, safeFilename, written)
			if err != nil {
				os.Remove(destPath)
				log.Printf("Error inserting UAT build: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to record build"})
				return
			}

			buildID, _ := result.LastInsertId()
			log.Printf("UAT build uploaded: %s (%s/%s) - %d bytes", version, platform, arch, written)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(UATBuild{
				ID:       buildID,
				Version:  version,
				Platform: platform,
				Arch:     arch,
				Filename: safeFilename,
				FileSize: written,
			})

		case http.MethodGet:
			rows, err := db.Query(`SELECT id, version, platform, arch, filename, file_size, created_at FROM uat_builds ORDER BY created_at DESC`)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to query builds"})
				return
			}
			defer rows.Close()

			builds := []UATBuild{}
			for rows.Next() {
				var b UATBuild
				if err := rows.Scan(&b.ID, &b.Version, &b.Platform, &b.Arch, &b.Filename, &b.FileSize, &b.CreatedAt); err != nil {
					continue
				}
				builds = append(builds, b)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"builds": builds, "total": len(builds)})

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Delete a UAT build
	http.HandleFunc("/api/admin/uat-builds/", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/uat-builds/")
		buildID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid build ID"})
			return
		}

		var filename string
		err = db.QueryRow(`SELECT filename FROM uat_builds WHERE id = ?`, buildID).Scan(&filename)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Build not found"})
			return
		}

		// Check if any active links reference this build
		var activeLinks int
		db.QueryRow(`SELECT COUNT(*) FROM uat_links WHERE build_id = ? AND revoked = 0 AND expires_at > datetime('now') AND use_count < max_uses`, buildID).Scan(&activeLinks)
		if activeLinks > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Build has active links", Details: fmt.Sprintf("%d active link(s) reference this build — revoke them first", activeLinks)})
			return
		}

		// Only remove the file if no other build record shares the same filename
		var otherBuilds int
		db.QueryRow(`SELECT COUNT(*) FROM uat_builds WHERE filename = ? AND id != ?`, filename, buildID).Scan(&otherBuilds)
		if otherBuilds == 0 {
			os.Remove(filepath.Join(uatBuildsDir, filename))
		}
		db.Exec(`DELETE FROM uat_builds WHERE id = ?`, buildID)

		log.Printf("UAT build deleted: ID %d (%s)", buildID, filename)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "id": buildID})
	})

	// Create and list UAT links
	http.HandleFunc("/api/admin/uat-links", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		switch r.Method {
		case http.MethodPost:
			var req CreateUATLinkRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON", Details: err.Error()})
				return
			}

			if req.IssuedTo == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "issuedTo is required"})
				return
			}

			// Resolve the target: either a UAT build or a shared file
			var buildID int64
			var sharedFileID int64
			if req.SharedFileID > 0 {
				// Verify shared file exists
				err := db.QueryRow(`SELECT id FROM shared_files WHERE id = ?`, req.SharedFileID).Scan(&sharedFileID)
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(ErrorResponse{Error: "Shared file not found", Details: fmt.Sprintf("No shared file with ID %d", req.SharedFileID)})
					return
				}
			} else {
				// Find the build
				err := db.QueryRow(`SELECT id FROM uat_builds WHERE version = ? AND platform = ? AND arch = ? ORDER BY created_at DESC LIMIT 1`,
					req.Version, req.Platform, req.Arch).Scan(&buildID)
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(ErrorResponse{Error: "No build found", Details: fmt.Sprintf("No build for %s/%s/%s", req.Version, req.Platform, req.Arch)})
					return
				}
			}

			// Defaults
			if req.MaxUses <= 0 {
				req.MaxUses = 3
			}
			if req.ExpiresInHours <= 0 {
				req.ExpiresInHours = 168 // 7 days
			}

			token, err := generateToken()
			if err != nil {
				log.Printf("Error generating token: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate token"})
				return
			}

			expiresAt := time.Now().UTC().Add(time.Duration(req.ExpiresInHours) * time.Hour)
			expiresAtStr := expiresAt.Format("2006-01-02 15:04:05")

			if sharedFileID > 0 {
				_, err = db.Exec(`INSERT INTO uat_links (token, issued_to, build_id, shared_file_id, max_uses, expires_at) VALUES (?, ?, 0, ?, ?, ?)`,
					token, req.IssuedTo, sharedFileID, req.MaxUses, expiresAtStr)
			} else {
				_, err = db.Exec(`INSERT INTO uat_links (token, issued_to, build_id, max_uses, expires_at) VALUES (?, ?, ?, ?, ?)`,
					token, req.IssuedTo, buildID, req.MaxUses, expiresAtStr)
			}
			if err != nil {
				log.Printf("Error creating UAT link: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create link"})
				return
			}

			// Build the download URL using the request host
			publicHost := os.Getenv("PUBLIC_HOST")
			if publicHost == "" {
				publicHost = "https://" + r.Host
			}
			downloadLink := fmt.Sprintf("%s/api/uat/download/%s", publicHost, token)

			log.Printf("UAT link created for %s: %s/%s/%s (expires %s)", req.IssuedTo, req.Version, req.Platform, req.Arch, expiresAt.Format(time.RFC3339))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(CreateUATLinkResponse{
				Token:        token,
				DownloadLink: downloadLink,
				IssuedTo:     req.IssuedTo,
				Version:      req.Version,
				Platform:     req.Platform,
				Arch:         req.Arch,
				MaxUses:      req.MaxUses,
				ExpiresAt:    expiresAt.Format(time.RFC3339),
			})

		case http.MethodGet:
			status := r.URL.Query().Get("status")
			if status == "" {
				status = "active"
			}

			var query string
			switch status {
			case "active":
				query = `SELECT l.id, l.token, l.issued_to, l.build_id, COALESCE(b.version, sf.description, ''), COALESCE(b.platform, ''), COALESCE(b.arch, ''), l.max_uses, l.use_count, l.expires_at, l.revoked, l.created_at, COALESCE(l.last_used_at, '')
					FROM uat_links l
					LEFT JOIN uat_builds b ON l.build_id = b.id AND l.shared_file_id IS NULL
					LEFT JOIN shared_files sf ON l.shared_file_id = sf.id
					WHERE l.revoked = 0 AND l.expires_at > datetime('now') AND l.use_count < l.max_uses
					ORDER BY l.created_at DESC`
			case "expired":
				query = `SELECT l.id, l.token, l.issued_to, l.build_id, COALESCE(b.version, sf.description, ''), COALESCE(b.platform, ''), COALESCE(b.arch, ''), l.max_uses, l.use_count, l.expires_at, l.revoked, l.created_at, COALESCE(l.last_used_at, '')
					FROM uat_links l
					LEFT JOIN uat_builds b ON l.build_id = b.id AND l.shared_file_id IS NULL
					LEFT JOIN shared_files sf ON l.shared_file_id = sf.id
					WHERE l.revoked = 1 OR l.expires_at <= datetime('now') OR l.use_count >= l.max_uses
					ORDER BY l.created_at DESC`
			case "all":
				query = `SELECT l.id, l.token, l.issued_to, l.build_id, COALESCE(b.version, sf.description, ''), COALESCE(b.platform, ''), COALESCE(b.arch, ''), l.max_uses, l.use_count, l.expires_at, l.revoked, l.created_at, COALESCE(l.last_used_at, '')
					FROM uat_links l
					LEFT JOIN uat_builds b ON l.build_id = b.id AND l.shared_file_id IS NULL
					LEFT JOIN shared_files sf ON l.shared_file_id = sf.id
					ORDER BY l.created_at DESC`
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid status filter", Details: "Use: active, expired, or all"})
				return
			}

			rows, err := db.Query(query)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to query links"})
				return
			}
			defer rows.Close()

			links := []UATLink{}
			for rows.Next() {
				var l UATLink
				var revokedInt int
				if err := rows.Scan(&l.ID, &l.Token, &l.IssuedTo, &l.BuildID, &l.Version, &l.Platform, &l.Arch, &l.MaxUses, &l.UseCount, &l.ExpiresAt, &revokedInt, &l.CreatedAt, &l.LastUsedAt); err != nil {
					continue
				}
				l.Revoked = revokedInt != 0
				links = append(links, l)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"links": links, "total": len(links)})

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Revoke a UAT link
	http.HandleFunc("/api/admin/uat-links/", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		token := strings.TrimPrefix(r.URL.Path, "/api/admin/uat-links/")
		if token == "" || len(token) != 64 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid token"})
			return
		}

		switch r.Method {
		case http.MethodDelete:
			result, err := db.Exec(`UPDATE uat_links SET revoked = 1 WHERE token = ?`, token)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to revoke link"})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Link not found"})
				return
			}

			log.Printf("UAT link revoked: %s", token)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "revoked", "token": token})

		case http.MethodPatch:
			result, err := db.Exec(`UPDATE uat_links SET use_count = 0, last_used_at = NULL WHERE token = ?`, token)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to reset link"})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Link not found"})
				return
			}

			log.Printf("UAT link download count reset: %s", token)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "reset", "token": token})

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Shared files - upload and list
	http.HandleFunc("/api/admin/shared-files", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		switch r.Method {
		case http.MethodPost:
			if err := r.ParseMultipartForm(500 << 20); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to parse upload", Details: err.Error()})
				return
			}

			description := r.FormValue("description")

			file, header, err := r.FormFile("file")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing file"})
				return
			}
			defer file.Close()

			originalName := filepath.Base(header.Filename)
			// Prefix with random hex to avoid collisions
			prefix := make([]byte, 8)
			rand.Read(prefix)
			safeFilename := fmt.Sprintf("shared-%s-%s", hex.EncodeToString(prefix), originalName)
			destPath := filepath.Join(uatBuildsDir, safeFilename)

			out, err := os.Create(destPath)
			if err != nil {
				log.Printf("Error creating shared file: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to store file"})
				return
			}
			defer out.Close()

			written, err := io.Copy(out, file)
			if err != nil {
				os.Remove(destPath)
				log.Printf("Error writing shared file: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to write file"})
				return
			}

			result, err := db.Exec(`INSERT INTO shared_files (filename, original_name, file_size, description) VALUES (?, ?, ?, ?)`,
				safeFilename, originalName, written, description)
			if err != nil {
				os.Remove(destPath)
				log.Printf("Error inserting shared file: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to record file"})
				return
			}

			fileID, _ := result.LastInsertId()
			log.Printf("Shared file uploaded: %s (%d bytes)", originalName, written)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(SharedFile{
				ID:           fileID,
				Filename:     safeFilename,
				OriginalName: originalName,
				FileSize:     written,
				Description:  description,
			})

		case http.MethodGet:
			rows, err := db.Query(`SELECT id, filename, original_name, file_size, description, created_at FROM shared_files ORDER BY created_at DESC`)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to query shared files"})
				return
			}
			defer rows.Close()

			files := []SharedFile{}
			for rows.Next() {
				var f SharedFile
				if err := rows.Scan(&f.ID, &f.Filename, &f.OriginalName, &f.FileSize, &f.Description, &f.CreatedAt); err != nil {
					continue
				}
				files = append(files, f)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"files": files, "total": len(files)})

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Delete a shared file
	http.HandleFunc("/api/admin/shared-files/", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/shared-files/")
		fileID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid file ID"})
			return
		}

		var filename string
		err = db.QueryRow(`SELECT filename FROM shared_files WHERE id = ?`, fileID).Scan(&filename)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "File not found"})
			return
		}

		// Check if any active links reference this file
		var activeLinks int
		db.QueryRow(`SELECT COUNT(*) FROM uat_links WHERE shared_file_id = ? AND revoked = 0 AND expires_at > datetime('now') AND use_count < max_uses`, fileID).Scan(&activeLinks)
		if activeLinks > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "File has active links", Details: fmt.Sprintf("%d active link(s) reference this file — revoke them first", activeLinks)})
			return
		}

		os.Remove(filepath.Join(uatBuildsDir, filename))
		db.Exec(`DELETE FROM shared_files WHERE id = ?`, fileID)

		log.Printf("Shared file deleted: ID %d (%s)", fileID, filename)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "id": fileID})
	})

	// UAT download - tester-facing endpoint
	http.HandleFunc("/api/uat/download/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		token := strings.TrimPrefix(r.URL.Path, "/api/uat/download/")
		if token == "" || len(token) != 64 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, uatErrorPage("Invalid Link", "This download link is not valid."))
			return
		}

		// Ignore link preview bots (Facebook, Slack, iMessage, WhatsApp, etc.)
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		if strings.Contains(ua, "facebookexternalhit") ||
			strings.Contains(ua, "facebot") ||
			strings.Contains(ua, "slackbot") ||
			strings.Contains(ua, "whatsapp") ||
			strings.Contains(ua, "telegrambot") ||
			strings.Contains(ua, "twitterbot") ||
			strings.Contains(ua, "linkedinbot") ||
			strings.Contains(ua, "discordbot") ||
			strings.Contains(ua, "applebot") ||
			strings.Contains(ua, "iframely") ||
			strings.Contains(ua, "preview") {
			w.WriteHeader(http.StatusOK)
			return
		}

		var linkID int64
		var filename, displayName string
		var maxUses, useCount int
		var expiresAt string
		var revoked int

		err := db.QueryRow(`SELECT l.id, COALESCE(sf.filename, b.filename), COALESCE(sf.original_name, b.filename), l.max_uses, l.use_count, l.expires_at, l.revoked
			FROM uat_links l
			LEFT JOIN uat_builds b ON l.build_id = b.id AND l.shared_file_id IS NULL
			LEFT JOIN shared_files sf ON l.shared_file_id = sf.id
			WHERE l.token = ?`, token).Scan(&linkID, &filename, &displayName, &maxUses, &useCount, &expiresAt, &revoked)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, uatErrorPage("Link Not Found", "This download link does not exist."))
			return
		}

		if revoked != 0 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, uatErrorPage("Link Revoked", "This download link has been revoked. Please contact the person who sent you this link."))
			return
		}

		expires, _ := time.Parse("2006-01-02 15:04:05", expiresAt)
		if !expires.IsZero() && time.Now().UTC().After(expires) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, uatErrorPage("Link Expired", "This download link has expired. Please contact the person who sent you this link for a new one."))
			return
		}

		if useCount >= maxUses {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, uatErrorPage("Download Limit Reached", "This download link has been used the maximum number of times. Please contact the person who sent you this link for a new one."))
			return
		}

		// Check file exists
		filePath := filepath.Join(uatBuildsDir, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("UAT build file missing: %s", filePath)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, uatErrorPage("File Not Available", "The build file is no longer available. Please contact the person who sent you this link."))
			return
		}

		// Update usage
		db.Exec(`UPDATE uat_links SET use_count = use_count + 1, last_used_at = datetime('now') WHERE id = ?`, linkID)

		log.Printf("UAT download: token=%s file=%s (use %d/%d)", token[:12]+"...", filename, useCount+1, maxUses)

		// Serve the file
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, displayName))
		http.ServeFile(w, r, filePath)
	})

	// UAT admin help - cheat sheet
	http.HandleFunc("/api/admin/uat-help", func(w http.ResponseWriter, r *http.Request) {
		if !validateAdminAuth(r, adminSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized"})
			return
		}

		scheme := "https"
		host := r.Host
		if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
			scheme = fwdProto
		}
		base := fmt.Sprintf("%s://%s", scheme, host)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, `UAT Download Link Management
=============================
Admin secret is in .env on droid1 — SSH in and 'cat .env' if you forget it

STEP 1: Upload a build
-----------------------
curl -sk -X POST %s/api/admin/uat-builds \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -F "file=@<path-to-file>" \
  -F "version=<version>" \
  -F "platform=<macos|windows|linux>" \
  -F "arch=<x86_64|aarch64>"

STEP 2: Create a link for a tester
-----------------------------------
curl -sk -X POST %s/api/admin/uat-links \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"issuedTo":"<name-or-email>","version":"<version>","platform":"<platform>","arch":"<arch>"}'

LIST BUILDS
-----------
curl -sk %s/api/admin/uat-builds \
  -H "Authorization: Bearer $ADMIN_SECRET"

LIST LINKS (active|expired|all)
-------------------------------
curl -sk "%s/api/admin/uat-links?status=active" \
  -H "Authorization: Bearer $ADMIN_SECRET"

RESET DOWNLOAD COUNT
--------------------
curl -sk -X PATCH %s/api/admin/uat-links/<token> \
  -H "Authorization: Bearer $ADMIN_SECRET"

REVOKE A LINK
-------------
curl -sk -X DELETE %s/api/admin/uat-links/<token> \
  -H "Authorization: Bearer $ADMIN_SECRET"

DELETE A BUILD
--------------
curl -sk -X DELETE %s/api/admin/uat-builds/<id> \
  -H "Authorization: Bearer $ADMIN_SECRET"

DEFAULTS
--------
- max_uses: 3 (override with "maxUses" in create link JSON)
- expiry: 7 days (override with "expiresInHours" in create link JSON)

NOTES
-----
- Upload the build first, then create links against it
- Testers just click the download link — no auth needed for them
- Set ADMIN_SECRET in your shell: export ADMIN_SECRET=<your-secret>
`, base, base, base, base, base, base, base)
	})

	// Start aggregation job
	scheduleAggregationJob(db)

	log.Println("Starting API server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
