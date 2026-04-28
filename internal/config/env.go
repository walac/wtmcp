package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// WorkDir returns the base directory for all wtmcp data.
// Checks WTMCP_WORKDIR env var (falls back to WHAT_THE_MCP_WORKDIR
// for backwards compat), then ~/.config/wtmcp.
func WorkDir() string {
	if dir := os.Getenv("WTMCP_WORKDIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("WHAT_THE_MCP_WORKDIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config", "wtmcp")
}

// EnvGroups maps credential group names to their variables.
// Group name is derived from the env.d filename without the .env
// extension (e.g., env.d/jira.env → group "jira").
type EnvGroups map[string]map[string]string

// Get returns the variables for a credential group, or nil if the
// group does not exist.
func (g EnvGroups) Get(group string) map[string]string {
	if g == nil {
		return nil
	}
	return g[group]
}

// EnvLoadResult holds both successfully loaded env groups and
// per-group errors for files that could not be loaded (bad
// permissions, symlinks, parse errors). Plugins whose credential
// group appears in Errors should be disabled, not loaded.
//
// DirError is set when the env.d directory itself has a problem
// (bad permissions, stat failure). When set, no files were read
// and Groups is empty — all credential-dependent plugins should
// be disabled.
type EnvLoadResult struct {
	Groups   EnvGroups
	Errors   map[string]string // group name → human-readable error
	DirError string            // directory-level error, if any
}

// ResolveEnvDir returns the env.d directory path from config or default.
func ResolveEnvDir(cfg *Config, workdir string) string {
	if cfg.EnvDir != "" {
		return ResolveEnvVars(cfg.EnvDir)
	}
	return filepath.Join(workdir, "env.d")
}

// LoadEnvGroups reads *.env files from envDir and returns them as scoped
// groups. Each file becomes a group keyed by its filename without
// the .env extension. Variables are NOT loaded into the process
// environment — they are only available through the returned map.
//
// Directory-level errors (bad permissions, stat failures) are stored
// in EnvLoadResult.DirError and no files are read — all credential-
// dependent plugins should be disabled. Per-file errors (bad
// permissions, symlinks, parse failures) are captured in
// EnvLoadResult.Errors and the file is skipped — other groups
// continue loading normally.
func LoadEnvGroups(envDir string) (EnvLoadResult, error) {
	result := EnvLoadResult{
		Groups: make(EnvGroups),
		Errors: make(map[string]string),
	}

	dirInfo, err := os.Stat(envDir)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		result.DirError = fmt.Sprintf("stat %s: %v", envDir, err)
		return result, nil //nolint:nilerr // captured in DirError
	}
	if err := CheckPermissions(envDir, dirInfo); err != nil {
		result.DirError = err.Error()
		return result, nil //nolint:nilerr // captured in DirError
	}

	entries, err := os.ReadDir(envDir)
	if err != nil {
		result.DirError = fmt.Sprintf("read %s: %v", envDir, err)
		return result, nil //nolint:nilerr // captured in DirError
	}

	// Sort for deterministic order
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".env") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		group := strings.TrimSuffix(name, ".env")
		path := filepath.Join(envDir, name)

		vars, err := loadEnvFile(path)
		if err != nil {
			relPath := filepath.Join("env.d", name)
			result.Errors[group] = fmt.Sprintf("%s: %v", relPath, err)
			continue
		}
		result.Groups[group] = vars
		log.Printf("loaded env group: %s (%d vars)", group, len(vars))
	}

	return result, nil
}

// LoadSingleEnvGroup loads (or reloads) a single env.d file by
// group name. Performs symlink rejection, permission checks, and
// parsing — same validation as LoadEnvGroups. Used by the plugin
// reload path to re-read credentials after the user fixes permissions.
func LoadSingleEnvGroup(envDir, group string) (map[string]string, error) {
	path := filepath.Join(envDir, group+".env")
	return loadEnvFile(path)
}

// loadEnvFile validates and reads a single env.d file.
// Rejects symlinks, checks permissions, then parses.
func loadEnvFile(path string) (map[string]string, error) {
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := CheckPermissions(path, info); err != nil {
		return nil, err
	}

	return parseEnvFile(path)
}

// rejectSymlink returns an error if path is a symbolic link.
// Prevents credential injection via symlinks to attacker-controlled
// files outside the env.d directory.
func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	if info.Mode().Type()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink — env.d files must be regular files", path)
	}
	return nil
}

// CheckPermissions refuses to proceed if a file or directory has
// group or other read/write/execute bits set, like OpenSSH does for
// private keys.
func CheckPermissions(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf(
			"%s has mode %04o, must not be accessible by group/other — run: chmod %04o %s",
			path, mode, mode&0o700, path,
		)
	}
	return nil
}

// parseEnvFile reads a .env file and returns its variables as a map.
// Lines starting with # are comments. Empty lines are skipped.
// Format: KEY=VALUE (double-quoted and single-quoted values have
// quotes stripped). The "export" prefix is also stripped.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // env file path from config
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	vars := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip export prefix
		line = strings.TrimPrefix(line, "export ")

		// Split on first =
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Strip surrounding double quotes
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		// Strip surrounding single quotes
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}

		vars[key] = value
	}

	return vars, scanner.Err()
}

// StandardPaths returns the conventional paths derived from the workdir.
type StandardPaths struct {
	WorkDir        string
	ConfigFile     string
	EnvDir         string
	CredentialsDir string
	PluginsDir     string
	CacheDir       string
}

// Paths returns the standard directory layout for a workdir.
func Paths(workdir string) StandardPaths {
	return StandardPaths{
		WorkDir:        workdir,
		ConfigFile:     filepath.Join(workdir, "config.yaml"),
		EnvDir:         filepath.Join(workdir, "env.d"),
		CredentialsDir: filepath.Join(workdir, "credentials"),
		PluginsDir:     filepath.Join(workdir, "plugins"),
		CacheDir:       filepath.Join(workdir, "cache"),
	}
}
