package sso

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type TokenCache struct {
	AccessToken  string    `json:"accessToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	RefreshToken string    `json:"refreshToken"`
	ClientId     string    `json:"clientId"`
	ClientSecret string    `json:"clientSecret"`
	StartUrl     string    `json:"startUrl"`
	Region       string    `json:"region"`
}

func getTokenCachePath(startURL string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	cacheDir := filepath.Join(homeDir, ".aws", "sso", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", err
	}

	hash := fmt.Sprintf("%x", sha1.Sum([]byte(startURL)))
	return filepath.Join(cacheDir, hash+".json"), nil
}

func LoadTokenCache(startURL string) (*TokenCache, error) {
	path, err := getTokenCachePath(startURL)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var token TokenCache
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func SaveTokenCache(token *TokenCache) error {
	path, err := getTokenCachePath(token.StartUrl)
	if err != nil {
		return err
	}

	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func DeleteTokenCache(startURL string) error {
	path, err := getTokenCachePath(startURL)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (t *TokenCache) IsFresh() bool {
	if t == nil {
		return false
	}
	return time.Now().Add(tokenExpirySkew).Before(t.ExpiresAt)
}

func (t *TokenCache) CanRefresh() bool {
	if t == nil {
		return false
	}
	return t.RefreshToken != "" && t.ClientId != "" && t.ClientSecret != ""
}

// tokenExpirySkew treats tokens as expired early so we refresh before the server
// rejects them; without it we'd race server-side expiry and surface a 401.
const tokenExpirySkew = 60 * time.Second

func ClearTokenCache() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cacheDir := filepath.Join(homeDir, ".aws", "sso", "cache")

	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return nil
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			cachePath := filepath.Join(cacheDir, entry.Name())
			if err := os.Remove(cachePath); err != nil {
				return err
			}
		}
	}

	return nil
}
