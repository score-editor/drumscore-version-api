package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type VersionInfo struct {
	Version            string `json:"version"`
	Build              string `json:"build"`
	ReleaseDate        string `json:"releaseDate"`
	DownloadURL        string `json:"downloadUrl"`
	MinSupportedVersion string `json:"minSupportedVersion"`
	ReleaseNotes       string `json:"releaseNotes,omitempty"`
}

type Config struct {
	mu       sync.RWMutex
	data     *VersionInfo
	filePath string
	lastMod  time.Time
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

	// Update last modified time
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

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/app/config/version.json"
	}

	config := NewConfig(configPath)

	// Initial load
	if err := config.Load(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Start background reloader - checks every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if err := config.CheckAndReload(); err != nil {
				log.Printf("Error reloading config: %v", err)
			}
		}
	}()

	http.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		versionInfo := config.Get()
		if versionInfo == nil {
			http.Error(w, "Version information not available", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes
		
		if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		versionInfo := config.Get()
		if versionInfo == nil {
			http.Error(w, "Unhealthy", http.StatusServiceUnavailable)
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
