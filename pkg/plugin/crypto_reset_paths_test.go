package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Regression test for a real bug found in a pre-submission audit:
// handleCryptoReset used to hardcode "brain-agent.db", while NewApp derives
// the real DB filename from the installed plugin directory name (so a
// forked/rebranded install, e.g. directory "my-brain-agent", gets its own
// "my-brain-agent.db"). The mismatch meant a fork's crypto-reset endpoint
// renamed a file that was never the real DB, silently no-opped, and still
// reported "crypto reset successful" -- a false-positive on the one button
// whose entire job is disaster recovery. cryptoResetPaths must derive the
// same DB filename NewApp/InitDB would for the same plugin directory name.
//
// Also covers a second, later audit finding: the AES/HMAC key filenames used
// to be fixed regardless of org, so any org's Admin hitting /crypto/reset
// rotated key material every OTHER org's already-encrypted rows depended on
// -- a cross-org denial of service. Both key paths must now carry the same
// org suffix as the DB path (see orgSuffixedName).
func TestCryptoResetPaths_DBFilenameMatchesPluginDirName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		pluginDirName   string
		orgID           int64
		wantDBPath      string
		wantAESKeyPath  string
		wantHMACKeyPath string
	}{
		{
			"default org, standard install", "brain-agent", 1,
			"/var/lib/grafana/brain-agent.db",
			"/var/lib/grafana/brain_aes.key",
			"/var/lib/grafana/brain_hmac.key",
		},
		{
			"zero-value OrgID (unset) also keeps unsuffixed names", "brain-agent", 0,
			"/var/lib/grafana/brain-agent.db",
			"/var/lib/grafana/brain_aes.key",
			"/var/lib/grafana/brain_hmac.key",
		},
		{
			"default org, forked install", "my-forked-brain-agent", 1,
			"/var/lib/grafana/my-forked-brain-agent.db",
			"/var/lib/grafana/brain_aes.key",
			"/var/lib/grafana/brain_hmac.key",
		},
		{
			"non-default org gets suffixed DB and suffixed keys", "brain-agent", 7,
			"/var/lib/grafana/brain-agent-org7.db",
			"/var/lib/grafana/brain_aes-org7.key",
			"/var/lib/grafana/brain_hmac-org7.key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbName := orgSuffixedName(c.pluginDirName, c.orgID)
			keyPath, hmacKeyPath, dbPath := cryptoResetPaths("/var/lib/grafana", dbName, c.orgID)
			if dbPath != c.wantDBPath {
				t.Errorf("cryptoResetPaths dbPath = %q, want %q", dbPath, c.wantDBPath)
			}
			if keyPath != c.wantAESKeyPath {
				t.Errorf("cryptoResetPaths keyPath = %q, want %q", keyPath, c.wantAESKeyPath)
			}
			if hmacKeyPath != c.wantHMACKeyPath {
				t.Errorf("cryptoResetPaths hmacKeyPath = %q, want %q", hmacKeyPath, c.wantHMACKeyPath)
			}
		})
	}
}

// Security-audit finding M2: a real (non-IsNotExist) error partway through
// backing up the 3 crypto-reset files must not leave the group half-renamed
// -- e.g. the key backed up but the database left in place, which InitDB
// would then reinitialize against, producing a real mixed state.
func TestBackupFilesAtomically_RollsBackOnPartialFailure(t *testing.T) {
	dataDir := t.TempDir()

	keyPath := filepath.Join(dataDir, "brain_aes.key")
	hmacKeyPath := filepath.Join(dataDir, "brain_hmac.key")
	dbPath := filepath.Join(dataDir, "brain-agent.db")

	if err := os.WriteFile(keyPath, []byte("key-content"), 0600); err != nil {
		t.Fatalf("seed keyPath: %v", err)
	}
	if err := os.WriteFile(hmacKeyPath, []byte("hmac-content"), 0600); err != nil {
		t.Fatalf("seed hmacKeyPath: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("db-content"), 0600); err != nil {
		t.Fatalf("seed dbPath: %v", err)
	}

	// Pre-create hmacKeyPath's backup destination as a non-empty directory --
	// os.Rename onto an existing non-empty directory fails with a real
	// error (ENOTEMPTY/EEXIST), never os.IsNotExist, regardless of whether
	// the test happens to run as root (a plain permission-denied scenario
	// would be silently bypassed by root, unlike this one).
	hmacBackupPath := fmt.Sprintf("%s.bkp_1234", hmacKeyPath)
	if err := os.MkdirAll(hmacBackupPath, 0755); err != nil {
		t.Fatalf("seed conflicting backup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hmacBackupPath, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatalf("seed file inside conflicting backup dir: %v", err)
	}

	err := backupFilesAtomically(dataDir, []string{keyPath, hmacKeyPath, dbPath}, 1234)
	if err == nil {
		t.Fatal("expected an error backing up hmacKeyPath onto an occupied non-empty directory, got nil")
	}

	// keyPath was renamed first and must have been rolled back.
	if _, statErr := os.Stat(keyPath); statErr != nil {
		t.Errorf("keyPath was not rolled back to its original location: %v", statErr)
	}
	if _, statErr := os.Stat(fmt.Sprintf("%s.bkp_1234", keyPath)); statErr == nil {
		t.Error("keyPath's backup file should have been rolled back (renamed back), but it still exists")
	}
	// dbPath was never reached (the loop aborted on the second path) and
	// must be untouched.
	if _, statErr := os.Stat(dbPath); statErr != nil {
		t.Errorf("dbPath should have been untouched, got: %v", statErr)
	}
}

func TestDetectPluginDirName_FallsBackWhenExecutablePathUnavailable(t *testing.T) {
	t.Parallel()

	// In the test binary itself, os.Executable() succeeds but doesn't point
	// at anything named "brain-agent" -- just confirm this never panics and
	// always returns a non-empty name, since it feeds directly into a
	// filesystem path.
	got := detectPluginDirName()
	if got == "" {
		t.Error("detectPluginDirName() returned empty string")
	}
}

// Security-audit finding H8 (remaining gap): two orgs on the same Grafana
// used to get two separate App instances that both opened the exact same
// SQLite file (and, in a later audit pass, the exact same encryption keys --
// see TestCryptoResetPaths_DBFilenameMatchesPluginDirName above), since
// neither the db nor the key filenames ever depended on OrgID.
// orgSuffixedName is the shared fix -- org 1 (Grafana's default/only org on a
// single-org install) keeps the original unsuffixed name so no existing
// install needs a migration; every other org gets its own file.
func TestOrgSuffixedName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		base  string
		orgID int64
		want  string
	}{
		{"default org keeps unsuffixed name", "brain-agent", 1, "brain-agent"},
		{"zero-value OrgID (unset) also keeps unsuffixed name", "brain-agent", 0, "brain-agent"},
		{"second org gets its own file", "brain-agent", 2, "brain-agent-org2"},
		{"large org id", "brain-agent", 4242, "brain-agent-org4242"},
		{"fork directory name is preserved in the suffix", "my-forked-brain-agent", 7, "my-forked-brain-agent-org7"},
		{"key basename gets the same treatment", "brain_aes", 7, "brain_aes-org7"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := orgSuffixedName(c.base, c.orgID)
			if got != c.want {
				t.Errorf("orgSuffixedName(%q, %d) = %q, want %q", c.base, c.orgID, got, c.want)
			}
		})
	}
}

// Two different orgs must resolve to two different real database files AND
// two different real key files on disk -- the actual observable behavior
// H8's remaining gap was about, not just the string-formatting helper in
// isolation.
func TestOrgSuffixedName_DifferentOrgsResolveToDifferentFiles(t *testing.T) {
	t.Parallel()

	org1Key, org1HMAC, org1DB := cryptoResetPaths("/var/lib/grafana", orgSuffixedName("brain-agent", 1), 1)
	org2Key, org2HMAC, org2DB := cryptoResetPaths("/var/lib/grafana", orgSuffixedName("brain-agent", 2), 2)

	if org1DB == org2DB {
		t.Errorf("org 1 and org 2 resolved to the same DB file %q -- they must never share a database", org1DB)
	}
	if org1Key == org2Key {
		t.Errorf("org 1 and org 2 resolved to the same AES key file %q -- an org's crypto reset must never orphan another org's data", org1Key)
	}
	if org1HMAC == org2HMAC {
		t.Errorf("org 1 and org 2 resolved to the same HMAC key file %q -- an org's crypto reset must never orphan another org's search index", org1HMAC)
	}
}
