package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LeGambiArt/wtmcp/internal/secrets/vault"
)

func TestWorkDir(t *testing.T) {
	// Default
	t.Setenv("WHAT_THE_MCP_WORKDIR", "")
	dir := WorkDir()
	if dir == "" || dir == "." {
		t.Error("default workdir should resolve to home-based path")
	}

	// Override
	t.Setenv("WHAT_THE_MCP_WORKDIR", "/custom/path")
	dir = WorkDir()
	if dir != "/custom/path" {
		t.Errorf("WorkDir() = %q, want /custom/path", dir)
	}
}

func TestLoadEnvGroups(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "jira.env"), []byte("JIRA_URL=https://jira.example.com\nJIRA_TOKEN=secret123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envDir, "google.env"), []byte("GOOGLE_PROJECT=myproject\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Non-.env files should be ignored
	if err := os.WriteFile(filepath.Join(envDir, "skip.txt"), []byte("SKIP=nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := LoadEnvGroups(envDir, EnvLoadOptions{})
	if err != nil {
		t.Fatalf("LoadEnvGroups: %v", err)
	}

	if len(result.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(result.Groups))
	}
	if len(result.Errors) != 0 {
		t.Fatalf("got %d errors, want 0: %v", len(result.Errors), result.Errors)
	}

	jira := result.Groups.Get("jira")
	if jira == nil {
		t.Fatal("expected jira group")
	}
	if jira["JIRA_URL"] != "https://jira.example.com" {
		t.Errorf("JIRA_URL = %q", jira["JIRA_URL"])
	}
	if jira["JIRA_TOKEN"] != "secret123" {
		t.Errorf("JIRA_TOKEN = %q", jira["JIRA_TOKEN"])
	}

	google := result.Groups.Get("google")
	if google == nil {
		t.Fatal("expected google group")
	}
	if google["GOOGLE_PROJECT"] != "myproject" {
		t.Errorf("GOOGLE_PROJECT = %q", google["GOOGLE_PROJECT"])
	}

	// Nonexistent group
	if result.Groups.Get("nonexistent") != nil {
		t.Error("expected nil for nonexistent group")
	}
}

func TestLoadEnvGroupsNotInProcessEnv(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	_ = os.Unsetenv("TEST_SCOPED_VAR")
	if err := os.WriteFile(filepath.Join(envDir, "test.env"), []byte("TEST_SCOPED_VAR=from_envd\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvGroups(envDir, EnvLoadOptions{})
	if err != nil {
		t.Fatalf("LoadEnvGroups: %v", err)
	}

	// Variable must NOT be in the process environment
	if val := os.Getenv("TEST_SCOPED_VAR"); val != "" {
		t.Errorf("TEST_SCOPED_VAR leaked into process env: %q", val)
	}
}

func TestLoadEnvGroupsMissingDir(t *testing.T) {
	result, err := LoadEnvGroups("/nonexistent/path/env.d", EnvLoadOptions{})
	if err != nil {
		t.Errorf("should not error on missing dir: %v", err)
	}
	if len(result.Groups) != 0 {
		t.Errorf("expected empty groups, got %d", len(result.Groups))
	}
}

func TestLoadEnvGroupsPartialOnBadFilePerms(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Good file
	if err := os.WriteFile(filepath.Join(envDir, "good.env"), []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Bad permissions — should be skipped, not fatal
	if err := os.WriteFile(filepath.Join(envDir, "bad.env"), []byte("SECRET=oops\n"), 0o644); err != nil { //nolint:gosec // intentionally insecure for test
		t.Fatal(err)
	}

	result, err := LoadEnvGroups(envDir, EnvLoadOptions{})
	if err != nil {
		t.Fatalf("should not return fatal error: %v", err)
	}

	// Good group loaded
	if result.Groups.Get("good") == nil {
		t.Error("expected good group to load")
	}

	// Bad group captured as error, not loaded
	if result.Groups.Get("bad") != nil {
		t.Error("bad group should not be loaded")
	}
	if errMsg, ok := result.Errors["bad"]; !ok {
		t.Error("expected error for bad group")
	} else if !strings.Contains(errMsg, "must not be accessible") {
		t.Errorf("error = %q, want permission error", errMsg)
	}
}

func TestLoadEnvGroupsLooseDirPermsSetsDirError(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o755); err != nil { //nolint:gosec // intentionally insecure for test
		t.Fatal(err)
	}

	result, err := LoadEnvGroups(envDir, EnvLoadOptions{})
	if err != nil {
		t.Fatalf("should not return fatal error: %v", err)
	}
	if result.DirError == "" {
		t.Fatal("expected DirError to be set")
	}
	if !strings.Contains(result.DirError, "must not be accessible") {
		t.Errorf("DirError = %q, want permission error", result.DirError)
	}
	if len(result.Groups) != 0 {
		t.Errorf("expected empty groups, got %d", len(result.Groups))
	}
}

func TestCheckPermissions(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPermissions(good, info); err != nil {
		t.Errorf("expected no error for 0600, got: %v", err)
	}

	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, nil, 0o644); err != nil { //nolint:gosec // intentionally insecure for test
		t.Fatal(err)
	}
	info, err = os.Stat(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPermissions(bad, info); err == nil {
		t.Error("expected error for 0644")
	}
}

func TestLoadEnvGroupsRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Good file alongside the symlink
	if err := os.WriteFile(filepath.Join(envDir, "good.env"), []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Symlink — should be captured as error, not fatal
	target := filepath.Join(dir, "real.env")
	if err := os.WriteFile(target, []byte("SECRET=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(envDir, "linked.env")); err != nil {
		t.Fatal(err)
	}

	result, err := LoadEnvGroups(envDir, EnvLoadOptions{})
	if err != nil {
		t.Fatalf("should not return fatal error: %v", err)
	}

	// Good file loaded
	if result.Groups.Get("good") == nil {
		t.Error("expected good group to load")
	}

	// Symlink captured as error
	if errMsg, ok := result.Errors["linked"]; !ok {
		t.Error("expected error for linked group")
	} else if !strings.Contains(errMsg, "symlink") {
		t.Errorf("error = %q, want symlink error", errMsg)
	}
}

func TestLoadSingleEnvGroup(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "mygroup.env"), []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	vars, err := LoadSingleEnvGroup(envDir, "mygroup", EnvLoadOptions{})
	if err != nil {
		t.Fatalf("LoadSingleEnvGroup: %v", err)
	}
	if vars["KEY"] != "value" {
		t.Errorf("KEY = %q", vars["KEY"])
	}
}

func TestLoadSingleEnvGroupBadPerms(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "bad.env"), []byte("KEY=value\n"), 0o644); err != nil { //nolint:gosec // intentionally insecure for test
		t.Fatal(err)
	}

	_, err := LoadSingleEnvGroup(envDir, "bad", EnvLoadOptions{})
	if err == nil {
		t.Fatal("expected error for bad permissions")
	}
	if !strings.Contains(err.Error(), "must not be accessible") {
		t.Errorf("error = %q", err)
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "test.env")

	content := `
# Comment line
PLAIN_VAR=plain_value
QUOTED_VAR="quoted value"
SINGLE_QUOTED='single quoted'
export EXPORTED_VAR=exported_value
  SPACED_VAR = spaced_value

EMPTY_LINE_ABOVE=yes
`
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	vars, err := parseEnvFile(envFile)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"PLAIN_VAR":        "plain_value",
		"QUOTED_VAR":       "quoted value",
		"SINGLE_QUOTED":    "single quoted",
		"EXPORTED_VAR":     "exported_value",
		"SPACED_VAR":       "spaced_value",
		"EMPTY_LINE_ABOVE": "yes",
	}

	for key, want := range tests {
		if got := vars[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestLoadEnvGroupsVaultEncrypted(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	password := []byte("test-password")
	plaintext := []byte("SECRET_KEY=vault-decrypted-value\nAPI_URL=https://api.example.com\n")

	encrypted, err := vault.Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "secure.env"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envDir, "plain.env"), []byte("PLAIN_KEY=plain-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := EnvLoadOptions{
		VaultPassword: func(_ string) ([]byte, error) {
			return password, nil
		},
	}
	result, err := LoadEnvGroups(envDir, opts)
	if err != nil {
		t.Fatalf("LoadEnvGroups: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}

	secureVars := result.Groups["secure"]
	if secureVars == nil {
		t.Fatal("missing 'secure' group")
	}
	if secureVars["SECRET_KEY"] != "vault-decrypted-value" {
		t.Errorf("SECRET_KEY = %q", secureVars["SECRET_KEY"])
	}
	if secureVars["API_URL"] != "https://api.example.com" {
		t.Errorf("API_URL = %q", secureVars["API_URL"])
	}

	plainVars := result.Groups["plain"]
	if plainVars == nil {
		t.Fatal("missing 'plain' group")
	}
	if plainVars["PLAIN_KEY"] != "plain-value" {
		t.Errorf("PLAIN_KEY = %q", plainVars["PLAIN_KEY"])
	}
}

func TestLoadEnvGroupsVaultNoPassword(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	encrypted, err := vault.Encrypt([]byte("KEY=value\n"), []byte("password"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "locked.env"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := LoadEnvGroups(envDir, EnvLoadOptions{})
	if err != nil {
		t.Fatalf("LoadEnvGroups: %v", err)
	}
	if _, ok := result.Errors["locked"]; !ok {
		t.Fatal("expected error for 'locked' group (no password)")
	}
	if !strings.Contains(result.Errors["locked"], "no vault password configured") {
		t.Errorf("error = %q", result.Errors["locked"])
	}
}

func TestLoadEnvGroupsVaultWrongPassword(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	encrypted, err := vault.Encrypt([]byte("KEY=value\n"), []byte("correct-password"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "wrong.env"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := EnvLoadOptions{
		VaultPassword: func(_ string) ([]byte, error) {
			return []byte("wrong-password"), nil
		},
	}
	result, err := LoadEnvGroups(envDir, opts)
	if err != nil {
		t.Fatalf("LoadEnvGroups: %v", err)
	}
	if _, ok := result.Errors["wrong"]; !ok {
		t.Fatal("expected error for 'wrong' group (wrong password)")
	}
	if !strings.Contains(result.Errors["wrong"], "HMAC verification failed") {
		t.Errorf("error = %q", result.Errors["wrong"])
	}
}

func TestLoadEnvGroupsVault12WithID(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env.d")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}

	prodPassword := []byte("prod-vault-password")
	plaintext := []byte("PROD_SECRET=vault-id-routed-value\n")

	encrypted, err := vault.EncryptWithID(plaintext, prodPassword, "prod")
	if err != nil {
		t.Fatalf("EncryptWithID: %v", err)
	}

	if err := os.WriteFile(filepath.Join(envDir, "service.env"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := EnvLoadOptions{
		VaultPassword: func(vaultID string) ([]byte, error) {
			if vaultID == "prod" {
				return prodPassword, nil
			}
			return nil, fmt.Errorf("unknown vault ID: %s", vaultID)
		},
	}
	result, err := LoadEnvGroups(envDir, opts)
	if err != nil {
		t.Fatalf("LoadEnvGroups: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}

	vars := result.Groups["service"]
	if vars == nil {
		t.Fatal("missing 'service' group")
	}
	if vars["PROD_SECRET"] != "vault-id-routed-value" {
		t.Errorf("PROD_SECRET = %q", vars["PROD_SECRET"])
	}
}

func TestPaths(t *testing.T) {
	p := Paths("/opt/wtmcp")

	if p.ConfigFile != "/opt/wtmcp/config.yaml" {
		t.Errorf("ConfigFile = %q", p.ConfigFile)
	}
	if p.EnvDir != "/opt/wtmcp/env.d" {
		t.Errorf("EnvDir = %q", p.EnvDir)
	}
	if p.CredentialsDir != "/opt/wtmcp/credentials" {
		t.Errorf("CredentialsDir = %q", p.CredentialsDir)
	}
	if p.PluginsDir != "/opt/wtmcp/plugins" {
		t.Errorf("PluginsDir = %q", p.PluginsDir)
	}
	if p.CacheDir != "/opt/wtmcp/cache" {
		t.Errorf("CacheDir = %q", p.CacheDir)
	}
}
