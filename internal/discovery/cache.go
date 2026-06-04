package discovery

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func cachePath(ssoProfile string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".bifrost")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(ssoProfile)))
	return filepath.Join(dir, "discovery-cache-"+hash+".json"), nil
}

// LoadCache reads the cached discovery results for the given SSO profile.
func LoadCache(ssoProfile string) (*Cache, error) {
	p, err := cachePath(ssoProfile)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		// Corrupt cache — delete and return nil so caller re-discovers.
		_ = os.Remove(p)
		return nil, nil
	}
	return &c, nil
}

// SaveCache writes discovery results to disk.
func SaveCache(ssoProfile string, resources []Resource) error {
	p, err := cachePath(ssoProfile)
	if err != nil {
		return err
	}
	c := Cache{
		Version:   CacheVersion,
		CachedAt:  time.Now(),
		Resources: resources,
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// IsCacheValid returns true if the cache is non-nil, written by the current
// schema version, and within the TTL. Older-version caches are treated as invalid
// so they're re-discovered (e.g. to populate VPC-matched bastions).
func IsCacheValid(c *Cache) bool {
	if c == nil {
		return false
	}
	if c.Version != CacheVersion {
		return false
	}
	return time.Since(c.CachedAt) < CacheTTL
}
