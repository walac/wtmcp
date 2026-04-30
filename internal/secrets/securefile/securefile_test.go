package securefile

import (
	"os"
	"testing"
)

func TestCreateWriteRead(t *testing.T) {
	sf, err := Create("test-create")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = sf.Close() }()

	data := []byte("secret-credential-data")
	if err := sf.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(sf.Path())
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", sf.Path(), err)
	}
	if string(got) != string(data) {
		t.Errorf("read back = %q, want %q", got, data)
	}
}

func TestCreateCloexecWriteRead(t *testing.T) {
	sf, err := CreateCloexec("test-cloexec")
	if err != nil {
		t.Fatalf("CreateCloexec: %v", err)
	}
	defer func() { _ = sf.Close() }()

	data := []byte("cloexec-credential-data")
	if err := sf.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(sf.Path())
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", sf.Path(), err)
	}
	if string(got) != string(data) {
		t.Errorf("read back = %q, want %q", got, data)
	}
}

func TestCloseReleasesPath(t *testing.T) {
	sf, err := Create("test-close")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := sf.Write([]byte("data")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := sf.Path()
	if err := sf.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.ReadFile(path); err == nil { //nolint:gosec // testing that closed path is unreadable
		t.Error("expected error reading closed securefile path")
	}
}

func TestWriteOverwrite(t *testing.T) {
	sf, err := Create("test-overwrite")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = sf.Close() }()

	if err := sf.Write([]byte("first-content-longer")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := sf.Write([]byte("second")); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	got, err := os.ReadFile(sf.Path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("read back = %q, want %q", got, "second")
	}
}

func TestTrackerClosePlugin(t *testing.T) {
	tracker := NewTracker()

	sf1, err := Create("plugin-a-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sf1.Write([]byte("a1"))
	tracker.TrackForPlugin("plugin-a", sf1)

	sf2, err := Create("plugin-a-2")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sf2.Write([]byte("a2"))
	tracker.TrackForPlugin("plugin-a", sf2)

	sf3, err := Create("plugin-b-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sf3.Write([]byte("b1"))
	tracker.TrackForPlugin("plugin-b", sf3)

	tracker.ClosePlugin("plugin-a")

	if _, err := os.ReadFile(sf1.Path()); err == nil {
		t.Error("plugin-a sf1 should be closed")
	}
	if _, err := os.ReadFile(sf2.Path()); err == nil {
		t.Error("plugin-a sf2 should be closed")
	}

	got, err := os.ReadFile(sf3.Path())
	if err != nil {
		t.Fatalf("plugin-b sf3 should still be readable: %v", err)
	}
	if string(got) != "b1" {
		t.Errorf("plugin-b sf3 = %q, want %q", got, "b1")
	}

	tracker.CloseAll()
}

func TestTrackerCloseAll(t *testing.T) {
	tracker := NewTracker()

	sf1, err := Create("all-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sf1.Write([]byte("1"))
	tracker.TrackForPlugin("p1", sf1)

	sf2, err := Create("all-2")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sf2.Write([]byte("2"))
	tracker.TrackForPlugin("p2", sf2)

	tracker.CloseAll()

	if _, err := os.ReadFile(sf1.Path()); err == nil {
		t.Error("sf1 should be closed after CloseAll")
	}
	if _, err := os.ReadFile(sf2.Path()); err == nil {
		t.Error("sf2 should be closed after CloseAll")
	}
}

func TestTrackerShadowDir(t *testing.T) {
	tracker := NewTracker()

	dir := t.TempDir()
	shadowDir := dir + "/shadow"
	if err := os.MkdirAll(shadowDir, 0o700); err != nil {
		t.Fatal(err)
	}

	tracker.TrackDirForPlugin("my-plugin", shadowDir)
	tracker.ClosePlugin("my-plugin")

	if _, err := os.Stat(shadowDir); !os.IsNotExist(err) {
		t.Error("shadow dir should be removed after ClosePlugin")
	}
}

func TestTrackerClosePluginDoesNotAffectOthers(t *testing.T) {
	tracker := NewTracker()

	sfA, err := Create("shared-group-a")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sfA.Write([]byte("a-data"))
	tracker.TrackForPlugin("google-calendar", sfA)

	sfB, err := Create("shared-group-b")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = sfB.Write([]byte("b-data"))
	tracker.TrackForPlugin("google-drive", sfB)

	tracker.ClosePlugin("google-calendar")

	if _, err := os.ReadFile(sfA.Path()); err == nil {
		t.Error("google-calendar securefile should be closed")
	}

	got, err := os.ReadFile(sfB.Path())
	if err != nil {
		t.Fatalf("google-drive securefile should still be readable: %v", err)
	}
	if string(got) != "b-data" {
		t.Errorf("google-drive data = %q, want %q", got, "b-data")
	}

	tracker.CloseAll()
}
