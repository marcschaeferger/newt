//go:build linux

package authdaemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCACertIfNotExistsEmptyContentsKeepsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	const existing = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExistingCA ca\n"
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	for _, force := range []bool{false, true} {
		if err := writeCACertIfNotExists(path, "", force); err != nil {
			t.Fatalf("force=%v: unexpected error: %v", force, err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != existing {
			t.Fatalf("force=%v: CA file changed to %q (%d bytes), want %q", force, got, len(got), existing)
		}
	}
}

func TestWriteCACertIfNotExistsEmptyContentsCreatesNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := writeCACertIfNotExists(path, "  \n", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no CA file to be created, stat err = %v", err)
	}
}
