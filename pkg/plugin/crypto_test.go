package plugin

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// Security-audit finding L3: a configured key is used directly, and no
// brain_aes.key file is created for it -- the whole point is keeping the
// key out of the same directory as the data it protects.
func TestInitCrypto_UsesProvidedKeyWithoutTouchingLocalFile(t *testing.T) {
	dataDir := t.TempDir()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	providedKey := base64.StdEncoding.EncodeToString(raw)

	app := &App{}
	if err := app.InitCrypto(dataDir, providedKey); err != nil {
		t.Fatalf("InitCrypto with a valid provided key failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dataDir, "brain_aes.key")); err == nil {
		t.Error("brain_aes.key should not be created when a key is provided via settings")
	}

	// Encrypt/decrypt round-trip proves the provided key is actually the
	// one in effect, not silently ignored in favor of a generated one.
	ciphertext, err := app.Encrypt("a secret fact")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	plaintext, err := app.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if plaintext != "a secret fact" {
		t.Errorf("round-trip = %q, want %q", plaintext, "a secret fact")
	}
}

func TestInitCrypto_RejectsInvalidProvidedKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"not valid base64", "not-valid-base64!!!"},
		{"wrong length (16 bytes)", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"wrong length (48 bytes)", base64.StdEncoding.EncodeToString(make([]byte, 48))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{}
			if err := app.InitCrypto(t.TempDir(), tc.key); err == nil {
				t.Error("expected an error for an invalid provided key, got nil")
			}
		})
	}
}

func TestInitCrypto_EmptyKeyFallsBackToLocalFile(t *testing.T) {
	dataDir := t.TempDir()

	app := &App{}
	if err := app.InitCrypto(dataDir, ""); err != nil {
		t.Fatalf("InitCrypto failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dataDir, "brain_aes.key")); err != nil {
		t.Errorf("brain_aes.key should be created when no key is provided, got: %v", err)
	}
}
