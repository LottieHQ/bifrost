// Package portcache persists the local port a user last forwarded to for a
// given (account, resource) pair so the next connection defaults to that
// choice rather than the well-known service port, which is often in use
// locally.
package portcache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// filename is the single JSON file holding all port mappings.
const filename = "port-cache.json"

// cachePath returns the absolute path of the port cache file, creating the
// parent directory with user-only permissions if it does not exist.
func cachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".bifrost")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, filename), nil
}

func key(accountID, resourceName string) string {
	return accountID + ":" + resourceName
}

// load reads the cache from disk. Missing or corrupt files return an empty
// map so callers can proceed with defaults.
func load() map[string]string {
	p, err := cachePath()
	if err != nil {
		return map[string]string{}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return map[string]string{}
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]string{}
	}
	return m
}

// Get returns the cached local port for (accountID, resourceName) and whether
// one was found.
func Get(accountID, resourceName string) (string, bool) {
	port, ok := load()[key(accountID, resourceName)]
	return port, ok
}

// Set writes the chosen local port for (accountID, resourceName) back to disk.
func Set(accountID, resourceName, port string) error {
	p, err := cachePath()
	if err != nil {
		return err
	}
	m := load()
	m[key(accountID, resourceName)] = port
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal port cache: %w", err)
	}
	return os.WriteFile(p, data, 0600)
}
