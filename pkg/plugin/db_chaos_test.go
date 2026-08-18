package plugin

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestChaosAndOWASPSecurity(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaos-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	app := &App{maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	ctx := context.Background()

	t.Run("SQL_Injection_Prevention", func(t *testing.T) {
		maliciousProject := "admin' OR 1=1; DROP TABLE memory_store; --"
		maliciousFact := "'); DELETE FROM memory_store; --"

		err := app.StoreMemory(ctx, maliciousProject, maliciousFact)
		if err != nil {
			t.Fatalf("StoreMemory failed on injection attempt: %v", err)
		}

		// Verify table still exists and data was inserted literally
		stats, err := app.GetProjectStats(ctx)
		if err != nil {
			t.Fatalf("Table was dropped or broken! %v", err)
		}

		if count := stats[maliciousProject]; count != 1 {
			t.Errorf("Literal insertion failed, got %d", count)
		}
	})

	t.Run("XSS_Payload_Storage", func(t *testing.T) {
		xssFact := "<script>alert('xss')</script><img src=x onerror=alert(1)>"
		err := app.StoreMemory(ctx, "frontend", xssFact)
		if err != nil {
			t.Fatalf("Failed to store XSS payload: %v", err)
		}

		res, err := app.SearchMemory(ctx, "frontend", "script", true)
		if err != nil || len(res) == 0 {
			t.Fatalf("Failed to retrieve XSS payload safely")
		}
		if res[0] != xssFact {
			t.Errorf("Payload mutated during storage: %v", res[0])
		}
	})

	t.Run("Cross_Project_Leakage_Tenancy", func(t *testing.T) {
		if err := app.StoreMemory(ctx, "project-A", "secret-password-123"); err != nil {
			t.Fatalf("StoreMemory failed: %v", err)
		}
		if err := app.StoreMemory(ctx, "project-B", "public-info"); err != nil {
			t.Fatalf("StoreMemory failed: %v", err)
		}

		// Search project B should never return project A data, even with wildcards
		res, err := app.SearchMemory(ctx, "project-B", "secret", true)
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}
		if len(res) > 0 && strings.Contains(res[0], "secret-password") {
			t.Errorf("TENANCY BROKEN! Project B saw Project A's data")
		}
	})

	t.Run("Massive_Payload_Chaos", func(t *testing.T) {
		// 5MB payload string
		massiveFact := strings.Repeat("A", 5*1024*1024)
		err := app.StoreMemory(ctx, "heavy-load", massiveFact)
		if err != nil {
			t.Fatalf("Failed to handle massive payload: %v", err)
		}

		// Attempt to search
		res, err := app.SearchMemory(ctx, "heavy-load", "AAAA", true)
		if err != nil || len(res) == 0 {
			t.Fatalf("Failed to search massive payload")
		}
	})

	t.Run("Delete_Memory_Function", func(t *testing.T) {
		if err := app.StoreMemory(ctx, "delete-test", "delete me please"); err != nil {
			t.Fatalf("StoreMemory failed: %v", err)
		}
		err := app.DeleteMemory(ctx, "delete-test", "delete me please")
		if err != nil {
			t.Fatalf("Failed to delete memory: %v", err)
		}

		err = app.DeleteMemory(ctx, "delete-test", "delete me please")
		if err == nil {
			t.Fatalf("Expected error when deleting non-existent fact")
		}
	})
}
