package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveVaultPassword_EnvVar(t *testing.T) {
	t.Setenv("WTMCP_VAULT_PASSWORD", "env-password")

	cfg := DefaultConfig()
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "env-password" {
		t.Errorf("got %q, want %q", password, "env-password")
	}

	// Env var should be unset after first read.
	if val, ok := os.LookupEnv("WTMCP_VAULT_PASSWORD"); ok {
		t.Errorf("WTMCP_VAULT_PASSWORD still set: %q", val)
	}

	// Second call should return cached value.
	password2, err := resolve("")
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if string(password2) != "env-password" {
		t.Errorf("cached value = %q, want %q", password2, "env-password")
	}
}

func TestResolveVaultPassword_EmptyEnvVar(t *testing.T) {
	t.Setenv("WTMCP_VAULT_PASSWORD", "")

	cfg := DefaultConfig()
	resolve := ResolveVaultPassword(cfg)

	_, err := resolve("")
	if err == nil {
		t.Fatal("expected error for empty env var + no file")
	}
	if !strings.Contains(err.Error(), "no vault password configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveVaultPassword_File(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte("file-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = passFile
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "file-password" {
		t.Errorf("got %q, want %q (trailing newline should be stripped)", password, "file-password")
	}
}

func TestResolveVaultPassword_FileNoNewline(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte("no-newline-password"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = passFile
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "no-newline-password" {
		t.Errorf("got %q, want %q", password, "no-newline-password")
	}
}

func TestResolveVaultPassword_FileEmpty(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = passFile
	resolve := ResolveVaultPassword(cfg)

	_, err := resolve("")
	if err == nil {
		t.Fatal("expected error for empty password file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveVaultPassword_FileBadPerms(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte("password"), 0o644); err != nil { //nolint:gosec // intentionally testing bad permissions
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = passFile
	resolve := ResolveVaultPassword(cfg)

	_, err := resolve("")
	if err == nil {
		t.Fatal("expected error for world-readable password file")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveVaultPassword_FileSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real-pass")
	if err := os.WriteFile(realFile, []byte("password"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "link-pass")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = symlink
	resolve := ResolveVaultPassword(cfg)

	_, err := resolve("")
	if err == nil {
		t.Fatal("expected error for symlinked password file")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveVaultPassword_VaultID(t *testing.T) {
	dir := t.TempDir()
	prodFile := filepath.Join(dir, "prod-pass")
	if err := os.WriteFile(prodFile, []byte("prod-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	devFile := filepath.Join(dir, "dev-pass")
	if err := os.WriteFile(devFile, []byte("dev-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultIDs = map[string]string{
		"prod": prodFile,
		"dev":  devFile,
	}
	resolve := ResolveVaultPassword(cfg)

	prod, err := resolve("prod")
	if err != nil {
		t.Fatalf("resolve prod: %v", err)
	}
	if string(prod) != "prod-password" {
		t.Errorf("prod = %q, want %q", prod, "prod-password")
	}

	dev, err := resolve("dev")
	if err != nil {
		t.Fatalf("resolve dev: %v", err)
	}
	if string(dev) != "dev-password" {
		t.Errorf("dev = %q, want %q", dev, "dev-password")
	}
}

func TestResolveVaultPassword_VaultIDEnvVar(t *testing.T) {
	t.Setenv("WTMCP_VAULT_PASSWORD_PROD", "prod-env-password")

	cfg := DefaultConfig()
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "prod-env-password" {
		t.Errorf("got %q, want %q", password, "prod-env-password")
	}

	if val, ok := os.LookupEnv("WTMCP_VAULT_PASSWORD_PROD"); ok {
		t.Errorf("WTMCP_VAULT_PASSWORD_PROD still set: %q", val)
	}
}

func TestResolveVaultPassword_VaultIDFallsBackToDefault(t *testing.T) {
	t.Setenv("WTMCP_VAULT_PASSWORD", "default-password")

	cfg := DefaultConfig()
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("unknown-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "default-password" {
		t.Errorf("got %q, want %q", password, "default-password")
	}
}

func TestResolveVaultPassword_EnvVarPrecedence(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte("file-password"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("WTMCP_VAULT_PASSWORD", "env-password")

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = passFile
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "env-password" {
		t.Errorf("env var should take precedence, got %q", password)
	}
}

func TestResolveVaultPassword_NoPasswordConfigured(t *testing.T) {
	cfg := DefaultConfig()
	resolve := ResolveVaultPassword(cfg)

	_, err := resolve("")
	if err == nil {
		t.Fatal("expected error when no password source configured")
	}
	if !strings.Contains(err.Error(), "no vault password configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveVaultPassword_PasswordFileEnvVar(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte("from-file-env\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("WTMCP_VAULT_PASSWORD_FILE", passFile)

	cfg := DefaultConfig()
	resolve := ResolveVaultPassword(cfg)

	password, err := resolve("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(password) != "from-file-env" {
		t.Errorf("got %q, want %q", password, "from-file-env")
	}
}

func TestValidateVaultIDConfigs(t *testing.T) {
	valid := map[string]string{
		"prod":    "/path/to/prod",
		"dev":     "/path/to/dev",
		"my-id_1": "/path/to/id",
	}
	if err := ValidateVaultIDConfigs(valid); err != nil {
		t.Errorf("unexpected error for valid IDs: %v", err)
	}

	invalid := map[string]string{
		"../../etc": "/path",
	}
	if err := ValidateVaultIDConfigs(invalid); err == nil {
		t.Error("expected error for invalid vault ID")
	}

	tooLong := map[string]string{
		strings.Repeat("a", 65): "/path",
	}
	if err := ValidateVaultIDConfigs(tooLong); err == nil {
		t.Error("expected error for vault ID too long")
	}
}

func TestResolveVaultPassword_Concurrent(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "vault-pass")
	if err := os.WriteFile(passFile, []byte("concurrent-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Secrets.VaultPasswordFile = passFile
	resolve := ResolveVaultPassword(cfg)

	const goroutines = 20
	errs := make(chan error, goroutines)
	for range goroutines {
		go func() {
			password, err := resolve("")
			if err != nil {
				errs <- err
				return
			}
			if string(password) != "concurrent-password" {
				errs <- fmt.Errorf("got %q, want %q", password, "concurrent-password")
				return
			}
			errs <- nil
		}()
	}

	for range goroutines {
		if err := <-errs; err != nil {
			t.Errorf("concurrent resolve: %v", err)
		}
	}
}

func TestStripTrailingNewline(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"password\n", "password"},
		{"password\r\n", "password"},
		{"password", "password"},
		{"pass\nword\n", "pass\nword"},
		{"\n", ""},
		{"\r\n", ""},
	}
	for _, tt := range tests {
		got := string(stripTrailingNewline([]byte(tt.input)))
		if got != tt.want {
			t.Errorf("stripTrailingNewline(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
