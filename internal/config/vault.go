package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

// SecretsConfig holds vault-related configuration. The
// VaultPasswordFile field points to a file containing the default
// vault password. VaultIDs maps vault ID labels to password files
// for multi-password support (Ansible Vault 1.2).
type SecretsConfig struct {
	VaultPasswordFile string            `yaml:"vault_password_file"`
	VaultIDs          map[string]string `yaml:"vault_ids"`
}

// vaultIDConfigPattern validates vault ID labels in config map keys.
var vaultIDConfigPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const maxVaultIDLen = 64

// ResolveVaultPassword returns a closure that resolves vault
// passwords by vault ID. The closure caches env var values on first
// read and unsets them from the process environment. File-based
// sources are re-read on each call to pick up rotations.
//
// The returned closure is safe for concurrent use.
func ResolveVaultPassword(cfg *Config) func(vaultID string) ([]byte, error) {
	var (
		mu       sync.Mutex
		envCache = make(map[string][]byte)
		consumed = make(map[string]bool)
	)

	return func(vaultID string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()

		if vaultID != "" {
			password, err := resolveNamedVaultID(cfg, vaultID, envCache, consumed)
			if err != nil {
				return nil, err
			}
			if password != nil {
				return password, nil
			}
		}

		return resolveDefaultPassword(cfg, envCache, consumed)
	}
}

// resolveNamedVaultID tries per-ID sources before falling back to
// the default chain.
func resolveNamedVaultID(cfg *Config, vaultID string, envCache map[string][]byte, consumed map[string]bool) ([]byte, error) {
	envKey := "WTMCP_VAULT_PASSWORD_" + strings.ToUpper(vaultID)
	if password := readEnvCached(envKey, envCache, consumed); password != nil {
		return password, nil
	}

	if cfg.Secrets.VaultIDs != nil {
		if path, ok := cfg.Secrets.VaultIDs[vaultID]; ok && path != "" {
			return ReadPasswordFile(path)
		}
	}

	return nil, nil
}

// resolveDefaultPassword tries the default password sources in
// priority order.
func resolveDefaultPassword(cfg *Config, envCache map[string][]byte, consumed map[string]bool) ([]byte, error) {
	if password := readEnvCached("WTMCP_VAULT_PASSWORD", envCache, consumed); password != nil {
		return password, nil
	}

	if fileEnv := readEnvCached("WTMCP_VAULT_PASSWORD_FILE", envCache, consumed); fileEnv != nil {
		return ReadPasswordFile(string(fileEnv))
	}

	if cfg.Secrets.VaultPasswordFile != "" {
		return ReadPasswordFile(cfg.Secrets.VaultPasswordFile)
	}

	return nil, fmt.Errorf("no vault password configured — " +
		"set WTMCP_VAULT_PASSWORD or secrets.vault_password_file in config.yaml")
}

// readEnvCached reads an environment variable, caching the value on
// first access and unsetting the env var to prevent child process
// inheritance. Returns nil if not set or empty.
func readEnvCached(key string, cache map[string][]byte, consumed map[string]bool) []byte {
	if cached, ok := cache[key]; ok {
		return cached
	}
	if consumed[key] {
		return nil
	}

	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		consumed[key] = true
		return nil
	}

	password := []byte(val)
	cache[key] = password
	os.Unsetenv(key) //nolint:errcheck // best-effort cleanup
	consumed[key] = true
	return password
}

// ReadPasswordFile reads a vault password from a file with full
// validation: symlink rejection, permission checks, and owner
// verification. Exactly one trailing newline is stripped to match
// ansible-vault behavior.
func ReadPasswordFile(path string) ([]byte, error) {
	if err := RejectSymlink(path); err != nil {
		return nil, fmt.Errorf("vault password file: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("vault password file: %w", err)
	}

	if err := CheckPermissions(path, info); err != nil {
		return nil, fmt.Errorf("vault password file: %w", err)
	}

	if err := checkOwner(path, info); err != nil {
		return nil, fmt.Errorf("vault password file: %w", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // path validated above
	if err != nil {
		return nil, fmt.Errorf("vault password file: %w", err)
	}

	data = stripTrailingNewline(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("vault password file is empty: %s", path)
	}

	return data, nil
}

// checkOwner verifies that the file is owned by the current user or
// root. Prevents reading password files owned by other users.
func checkOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	currentUID := os.Getuid()
	if currentUID < 0 {
		return nil
	}
	fileUID := stat.Uid
	if fileUID != uint32(currentUID) && fileUID != 0 { //nolint:gosec // uid is non-negative (checked above)
		return fmt.Errorf(
			"vault password file %s is owned by uid %d, "+
				"must be owned by current user (uid %d) or root",
			path, fileUID, currentUID,
		)
	}
	return nil
}

// stripTrailingNewline removes a trailing \r\n or \n to match
// ansible-vault password file behavior. Ansible's Python
// implementation uses str.strip(), which handles both.
func stripTrailingNewline(data []byte) []byte {
	if len(data) >= 2 && data[len(data)-2] == '\r' && data[len(data)-1] == '\n' {
		return data[:len(data)-2]
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		return data[:len(data)-1]
	}
	return data
}

// ValidateVaultIDConfigs validates vault ID labels in the config map.
func ValidateVaultIDConfigs(ids map[string]string) error {
	for id := range ids {
		if len(id) > maxVaultIDLen {
			return fmt.Errorf("vault ID %q in config too long: %d chars (max %d)", id, len(id), maxVaultIDLen)
		}
		if !vaultIDConfigPattern.MatchString(id) {
			return fmt.Errorf("invalid vault ID %q in config: must match [a-zA-Z0-9_-]+", id)
		}
	}
	return nil
}
