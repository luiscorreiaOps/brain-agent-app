package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

// ============================================================================
// AI & DEVELOPER WARNING: CRITICAL DATA LOSS PREVENTION
// ============================================================================
// Do NOT, under any circumstances, delete, rotate, or modify the "brain_aes.key"
// file in the data directory without explicit user consent to wipe all data.
//
// This file contains the symmetric AES-256-GCM key used to encrypt the
// SQLite database ("brain_memory.db") at rest. Since there is no master
// backdoor or key-escrow, losing this file means ALL encrypted memory facts
// will be PERMANENTLY IRRECOVERABLE.
//
// If you are writing cleanup scripts or resetting environments for tests,
// treat this file as sacred. If the key is lost, the data is gone forever.
// ============================================================================

// InitCrypto initializes or loads the AES-256 key for LGPD encryption at
// rest. providedKeyBase64, when non-empty, is used directly (decoded and
// validated as a 32-byte key) instead of touching brain_aes.key at all --
// security-audit finding L3: storing the key in the same directory as the
// database it protects means anyone with a copy of that directory (e.g. a
// backup) has both the lock and the key. When empty, this creates a
// brain_aes.key file in the data directory if it doesn't exist, exactly as
// before -- opt-in, not a required migration for existing installs.
func (a *App) InitCrypto(dataDir string, providedKeyBase64 string) error {
	if providedKeyBase64 != "" {
		key, err := base64.StdEncoding.DecodeString(providedKeyBase64)
		if err != nil {
			return fmt.Errorf("FATAL: configured encryption key is not valid base64: %w", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("FATAL: configured encryption key must decode to exactly 32 bytes (got %d) -- generate one with e.g. `openssl rand -base64 32`", len(key))
		}
		a.aesKey = key
		log.DefaultLogger.Info("Using AES-256 key from plugin settings (secureJsonData.encryptionKey), not the local key file")
		return nil
	}

	// Org-suffixed for every org but the default one (see orgSuffixedName,
	// H8's remaining gap) -- a.orgID is set once in NewApp, before InitDB
	// (and therefore this) is ever called, so it's always the right org by
	// the time this runs, including on a later /crypto/reset for that same
	// instance.
	keyPath := filepath.Join(dataDir, fmt.Sprintf("%s.key", orgSuffixedName("brain_aes", a.orgID)))

	// Try to load existing key
	if _, err := os.Stat(keyPath); err == nil {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("FATAL: existing AES key file found but could not be read: %w", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("FATAL: existing AES key is corrupted (invalid length: %d bytes). Admin intervention required to restore from backup or delete the key to start fresh", len(key))
		}

		a.aesKey = key
		log.DefaultLogger.Info("Loaded existing AES-256 key for LGPD encryption at rest")
		return nil
	}

	// If we reach here, the key does not exist. Generate a new 32-byte (256-bit) key.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Save the key using O_CREATE | O_EXCL to absolutely ensure we NEVER overwrite an existing file
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to securely create AES key file (prevented overwrite): %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("failed to write AES key: %w", err)
	}

	a.aesKey = key
	log.DefaultLogger.Info("Generated new AES-256 key for LGPD encryption at rest", "path", keyPath)
	return nil
}

// Encrypt string using AES-256-GCM and return Base64
func (a *App) Encrypt(plaintext string) (string, error) {
	if len(a.aesKey) == 0 {
		return "", fmt.Errorf("crypto not initialized")
	}

	block, err := aes.NewCipher(a.aesKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt Base64 string using AES-256-GCM
func (a *App) Decrypt(b64Ciphertext string) (string, error) {
	if len(a.aesKey) == 0 {
		return "", fmt.Errorf("crypto not initialized")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(a.aesKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
