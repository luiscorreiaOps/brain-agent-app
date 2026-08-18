package plugin

import (
	"context"
	"testing"
)

func TestDetectPII(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fact string
		want bool
	}{
		{"email", "Contact the on-call at jane.doe@example.com about this", true},
		{"cpf", "Customer CPF 123.456.789-09 was affected by the billing bug", true},
		{"us ssn", "Support ticket included the customer's SSN 219-09-9999 in the body", true},
		{"iban", "Refund failed for IBAN DE89370400440532013000, needs manual retry", true},
		{"eu vat", "Invoice mismatch for VAT number FR12345678901 in the billing export", true},
		{"mexican curp", "Onboarding failed for CURP GARC800101HDFRRL05 during identity verification", true},
		{"chilean rut", "Support ticket references RUT 12.345.678-5 for the affected account", true},
		{"latin american dni", "Refund blocked for DNI 20.123.456 pending manual review", true},
		{"ipv4", "The pod's internal IP was 10.0.5.23 during the incident", true},
		{"card-shaped digits", "Test card 4111 1111 1111 1111 was used to reproduce the charge bug", true},
		{"long token", "Rotated the service token to token-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", true},
		{"plain operational fact", "Vault pod restarted after an OOM kill during the memory leak incident", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := detectPII(tc.fact); got != tc.want {
				t.Errorf("detectPII(%q) = %v, want %v", tc.fact, got, tc.want)
			}
		})
	}
}

func TestStoreMemoryRecord_SkipsPIIScanByDefault(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "pii-project", "escalation contact: jane.doe@example.com"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	records, err := app.ListFactsWithMetadata(ctx, "pii-project")
	if err != nil {
		t.Fatalf("ListFactsWithMetadata failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].PIIDetected {
		t.Error("expected PIIDetected = false by default (explicit opt-in required), even for an email-containing fact")
	}
}

func TestStoreMemoryRecord_FlagsPIIWhenExplicitlyEnabled(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	app.piiDetectionEnabled = true

	if err := app.StoreMemory(ctx, "pii-off-project", "escalation contact: jane.doe@example.com"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	records, err := app.ListFactsWithMetadata(ctx, "pii-off-project")
	if err != nil {
		t.Fatalf("ListFactsWithMetadata failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if !records[0].PIIDetected {
		t.Error("expected PIIDetected = true once explicitly enabled, for an email-containing fact")
	}
}
