// Package config loads optional YAML configuration. Unknown keys are errors so
// that typos do not silently disable a safety limit.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config holds user-tunable settings. Defaults are conservative.
type Config struct {
	Threads           int     `yaml:"threads"`             // bounded concurrency for batches
	TimeoutSeconds    int     `yaml:"timeout_seconds"`     // per worker
	MaxFileSizeMB     int64   `yaml:"max_file_size_mb"`    // input limit
	WorkerMemoryMB    int64   `yaml:"worker_memory_mb"`    // RLIMIT_AS per worker
	RequireSandbox    bool    `yaml:"require_sandbox"`     // fail closed
	MaxBatchFiles     int     `yaml:"max_batch_files"`     // directory scan cap
	UnpackMaxMB       int64   `yaml:"unpack_max_mb"`       // largest accepted unpacked output
	UnpackMaxRatio    float64 `yaml:"unpack_max_ratio"`    // largest accepted expansion (bomb guard)
	MaxUnpackDepth    int     `yaml:"max_unpack_depth"`    // nested layers
	ExtractMaxMB      int64   `yaml:"extract_max_mb"`      // total extracted bytes per container
	ExtractMaxEntries int     `yaml:"extract_max_entries"` // entries per container
	UseDatabase       bool    `yaml:"use_database"`        // remember analysed files locally
	DatabasePath      string  `yaml:"database_path"`       // default $XDG_DATA_HOME/unpackr/db.json
	Banner            string  `yaml:"banner"`              // random | NNN | category | off
}

// Default returns the built-in configuration.
func Default() Config {
	t := runtime.NumCPU()
	if t > 4 {
		t = 4
	}
	return Config{
		Threads:           t,
		TimeoutSeconds:    120,
		MaxFileSizeMB:     2048,
		WorkerMemoryMB:    4096,
		MaxBatchFiles:     100000,
		UnpackMaxMB:       1024,
		UnpackMaxRatio:    200,
		MaxUnpackDepth:    3,
		ExtractMaxMB:      1024,
		ExtractMaxEntries: 20000,
		UseDatabase:       true,
		Banner:            "random",
	}
}

// Dir returns the configuration directory.
func Dir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "unpackr")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".config", "unpackr")
}

// DataDir returns the directory for the local database.
func DataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "unpackr")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".local", "share", "unpackr")
}

// StateDir returns the directory for small mutable state such as the last banner.
func StateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "unpackr")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".local", "state", "unpackr")
}

// Load reads path (or the default location if empty and present).
func Load(path string) (Config, error) {
	c := Default()
	explicit := path != ""
	if !explicit {
		if d := Dir(); d != "" {
			path = filepath.Join(d, "config.yaml")
		}
	}
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return c, nil
		}
		return c, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && err.Error() != "EOF" {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

// Validate rejects values that would disable limits by accident.
func (c Config) Validate() error {
	switch {
	case c.Threads < 1 || c.Threads > 256:
		return fmt.Errorf("threads must be 1-256")
	case c.TimeoutSeconds < 1:
		return fmt.Errorf("timeout_seconds must be positive")
	case c.MaxFileSizeMB < 1:
		return fmt.Errorf("max_file_size_mb must be positive")
	case c.WorkerMemoryMB < 64:
		return fmt.Errorf("worker_memory_mb must be at least 64")
	case c.UnpackMaxMB < 1 || c.UnpackMaxRatio < 1 || c.MaxUnpackDepth < 0 || c.MaxUnpackDepth > 10:
		return fmt.Errorf("unpack_max_mb and unpack_max_ratio must be positive and max_unpack_depth 0-10")
	case c.ExtractMaxMB < 1 || c.ExtractMaxEntries < 1:
		return fmt.Errorf("extract_max_mb and extract_max_entries must be positive")
	case c.MaxBatchFiles < 1:
		return fmt.Errorf("max_batch_files must be positive")
	}
	return nil
}
