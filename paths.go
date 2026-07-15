package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func pluginDataDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("CPA_TOKEN_USAGE_DIR")); dir != "" {
		return filepath.Clean(dir), nil
	}
	if runtime.GOOS == "windows" {
		if dir := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); dir != "" {
			return filepath.Join(dir, "CLIProxyAPI", "plugins", pluginID), nil
		}
	}
	if runtime.GOOS == "darwin" {
		if configDir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(configDir) != "" {
			return filepath.Join(configDir, "CLIProxyAPI", "plugins", pluginID), nil
		}
	}
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".cli-proxy-api", "plugins", pluginID), nil
	}
	configDir, configErr := os.UserConfigDir()
	if configErr == nil && strings.TrimSpace(configDir) != "" {
		return filepath.Join(configDir, "cli-proxy-api", "plugins", pluginID), nil
	}
	if err != nil {
		return "", err
	}
	if configErr != nil {
		return "", configErr
	}
	return "", errors.New("cannot determine plugin data directory")
}

func pluginDataDirBestEffort() string {
	dir, err := pluginDataDir()
	if err == nil && dir != "" {
		return dir
	}
	return filepath.Join(".", ".cli-proxy-api", "plugins", pluginID)
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return enforcePrivatePath(dir, true)
}

func ensurePrivateFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return enforcePrivatePath(path, false)
}

func defaultConfigCandidates() []string {
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		candidates = append(candidates,
			filepath.Join(home, ".cli-proxy-api", "config.yaml"),
			filepath.Join(home, "config.yaml"),
		)
	}
	if configDir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(configDir) != "" {
		candidates = append(candidates, filepath.Join(configDir, "cli-proxy-api", "config.yaml"))
	}
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "/root/config.yaml", "/root/.cli-proxy-api/config.yaml")
	}
	return uniquePaths(candidates)
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "." || path == "" {
			continue
		}
		key := path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(path)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, path)
	}
	return out
}
