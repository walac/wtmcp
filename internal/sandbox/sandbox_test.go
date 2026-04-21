package sandbox

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/LeGambiArt/wtmcp/internal/config"
)

func testConfig() config.SandboxConfig {
	return config.SandboxConfig{
		Defaults: config.SandboxResourceLimits{
			MaxMemoryMB:   512,
			MaxCPUPct:     100,
			MaxPIDs:       64,
			MaxFileSizeMB: 100,
		},
	}
}

func TestBuildProfileReadPaths(t *testing.T) {
	m := &Manager{
		cfg:     testConfig(),
		credDir: "/creds",
		dataDir: "/data",
	}

	info := PluginInfo{
		Name:            "gitlab",
		Dir:             "/opt/wtmcp/plugins/gitlab",
		Handler:         "./handler",
		CredentialGroup: "gitlab",
	}

	profile := m.BuildProfile(info)

	mustContain := []string{
		"/opt/wtmcp/plugins/gitlab",
		"/creds/gitlab",
		"/usr",
		"/lib",
		"/proc/self",
		"/dev/null",
		"/dev/urandom",
	}
	for _, p := range mustContain {
		if !contains(profile.ReadPaths, p) {
			t.Errorf("ReadPaths missing %q", p)
		}
	}

	if runtime.GOOS == "linux" {
		if !contains(profile.ReadPaths, "/lib64") {
			t.Error("ReadPaths missing /lib64 on Linux")
		}
	}
}

func TestBuildProfileWritePaths(t *testing.T) {
	m := &Manager{
		cfg:     testConfig(),
		dataDir: "/data",
	}

	info := PluginInfo{Name: "test-plugin", Dir: "/plugins/test", Handler: "./handler"}
	profile := m.BuildProfile(info)

	if len(profile.WritePaths) != 2 {
		t.Fatalf("WritePaths = %v, want 2 entries", profile.WritePaths)
	}

	tmpDir := m.TmpDir("test-plugin")
	dataDir := m.DataDir("test-plugin")

	if profile.WritePaths[0] != tmpDir {
		t.Errorf("WritePaths[0] = %q, want %q", profile.WritePaths[0], tmpDir)
	}
	if profile.WritePaths[1] != dataDir {
		t.Errorf("WritePaths[1] = %q, want %q", profile.WritePaths[1], dataDir)
	}
}

func TestBuildProfileNetNS(t *testing.T) {
	m := &Manager{cfg: testConfig(), dataDir: "/data"}
	info := PluginInfo{Name: "test", Dir: "/p", Handler: "./handler"}
	profile := m.BuildProfile(info)

	if !profile.UseNetNS {
		t.Error("UseNetNS should always be true")
	}
}

func TestBuildProfileResourceDefaults(t *testing.T) {
	m := &Manager{cfg: testConfig(), dataDir: "/data"}
	info := PluginInfo{Name: "test", Dir: "/p", Handler: "./handler"}
	profile := m.BuildProfile(info)

	if profile.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB = %d, want 512", profile.MaxMemoryMB)
	}
	if profile.MaxCPUPct != 100 {
		t.Errorf("MaxCPUPct = %d, want 100", profile.MaxCPUPct)
	}
	if profile.MaxPIDs != 64 {
		t.Errorf("MaxPIDs = %d, want 64", profile.MaxPIDs)
	}
	if profile.MaxFileSizeMB != 100 {
		t.Errorf("MaxFileSizeMB = %d, want 100", profile.MaxFileSizeMB)
	}
}

func TestBuildProfileResourceOverrides(t *testing.T) {
	cfg := testConfig()
	cfg.Plugins = map[string]config.SandboxResourceLimits{
		"big-plugin": {MaxMemoryMB: 2048, MaxPIDs: 128},
	}
	m := &Manager{cfg: cfg, dataDir: "/data"}

	info := PluginInfo{Name: "big-plugin", Dir: "/p", Handler: "./handler"}
	profile := m.BuildProfile(info)

	if profile.MaxMemoryMB != 2048 {
		t.Errorf("MaxMemoryMB = %d, want 2048 (override)", profile.MaxMemoryMB)
	}
	if profile.MaxPIDs != 128 {
		t.Errorf("MaxPIDs = %d, want 128 (override)", profile.MaxPIDs)
	}
	if profile.MaxCPUPct != 100 {
		t.Errorf("MaxCPUPct = %d, want 100 (default, not overridden)", profile.MaxCPUPct)
	}
}

func TestBuildProfilePythonPlugin(t *testing.T) {
	m := &Manager{cfg: testConfig(), dataDir: "/data"}

	goInfo := PluginInfo{Name: "go-plugin", Dir: "/p", Handler: "./handler"}
	pyInfo := PluginInfo{Name: "py-plugin", Dir: "/p", Handler: "./handler.py"}

	goProfile := m.BuildProfile(goInfo)
	pyProfile := m.BuildProfile(pyInfo)

	if len(pyProfile.ReadPaths) <= len(goProfile.ReadPaths) {
		t.Error("Python plugin should have more ReadPaths than Go plugin (interpreter)")
	}
}

func TestBuildProfileNoCredentialGroup(t *testing.T) {
	m := &Manager{cfg: testConfig(), credDir: "/creds", dataDir: "/data"}
	info := PluginInfo{Name: "test", Dir: "/p", Handler: "./handler"}

	profile := m.BuildProfile(info)

	for _, p := range profile.ReadPaths {
		if strings.HasPrefix(p, "/creds") {
			t.Errorf("ReadPaths should not include creds dir when no credential group: %v", p)
		}
	}
}

func TestPrepareDirs(t *testing.T) {
	tmpBase := t.TempDir()
	dataBase := t.TempDir()

	t.Setenv("TMPDIR", tmpBase)

	m := &Manager{cfg: testConfig(), dataDir: dataBase}
	tmpDir, dataDir, err := m.PrepareDirs("test-plugin")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Errorf("tmpdir not created: %s", tmpDir)
	}
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		t.Errorf("datadir not created: %s", dataDir)
	}

	info, _ := os.Stat(dataDir)
	if info.Mode().Perm() != 0o700 {
		t.Errorf("datadir mode = %o, want 700", info.Mode().Perm())
	}
}

func TestCleanupTmpDir(t *testing.T) {
	tmpBase := t.TempDir()
	t.Setenv("TMPDIR", tmpBase)

	m := &Manager{cfg: testConfig(), dataDir: t.TempDir()}
	_, _, err := m.PrepareDirs("cleanup-test")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := m.TmpDir("cleanup-test")
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Fatal("tmpdir should exist before cleanup")
	}

	m.CleanupTmpDir("cleanup-test")

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Error("tmpdir should be removed after cleanup")
	}
}

func TestSandboxConfigDefaults(t *testing.T) {
	cfg := config.SandboxConfig{}
	if !cfg.SandboxEnabled() {
		t.Error("sandbox should be enabled by default (nil Enabled)")
	}

	enabled := true
	cfg.Enabled = &enabled
	if !cfg.SandboxEnabled() {
		t.Error("sandbox should be enabled when Enabled=true")
	}

	disabled := false
	cfg.Enabled = &disabled
	if cfg.SandboxEnabled() {
		t.Error("sandbox should be disabled when Enabled=false")
	}
}

func TestIsPython(t *testing.T) {
	if !isPython("./handler.py") {
		t.Error("handler.py should be Python")
	}
	if isPython("./handler") {
		t.Error("./handler should not be Python")
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
