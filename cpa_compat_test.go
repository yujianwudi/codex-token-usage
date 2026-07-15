package main

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCPACompatibilityLockAndHarness(t *testing.T) {
	lockPath := filepath.Join("scripts", "cpa-compat.lock")
	file, err := os.Open(lockPath)
	if err != nil {
		t.Fatalf("open %s: %v", lockPath, err)
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("invalid lock line %q", line)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", lockPath, err)
	}

	if values["CPA_REPOSITORY"] != "https://github.com/router-for-me/CLIProxyAPI.git" {
		t.Fatalf("CPA_REPOSITORY = %q", values["CPA_REPOSITORY"])
	}
	commit := values["CPA_COMMIT"]
	decoded, err := hex.DecodeString(commit)
	if err != nil || len(decoded) != 20 || strings.ToLower(commit) != commit {
		t.Fatalf("CPA_COMMIT = %q, want a lowercase 40-character Git commit", commit)
	}
	if values["CPA_ABI_VERSION"] != "1" || values["CPA_SCHEMA_VERSION"] != "1" {
		t.Fatalf("CPA contract versions = ABI %q schema %q", values["CPA_ABI_VERSION"], values["CPA_SCHEMA_VERSION"])
	}

	for _, path := range []string{
		filepath.Join("scripts", "check-cpa-compat.sh"),
		filepath.Join("scripts", "cpa-compat", "plugin_compat_test.go.txt"),
	} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("compatibility asset %s is invalid: info=%v err=%v", path, info, err)
		}
	}
}
