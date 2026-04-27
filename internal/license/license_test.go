package license

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	lic := &License{
		Organization: "Acme Corp",
		Features:     []string{FeatureAnalyze, FeatureReport},
		IssuedAt:     time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second),
	}
	Sign(lic)
	if lic.Signature == "" {
		t.Fatal("Sign() did not set Signature")
	}
	if !verify(lic) {
		t.Error("verify() returned false for freshly signed license")
	}
}

func TestVerifyTamperedOrg(t *testing.T) {
	lic := &License{
		Organization: "Acme Corp",
		Features:     []string{FeatureAnalyze},
		IssuedAt:     time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second),
	}
	Sign(lic)
	lic.Organization = "Evil Corp" // tamper
	if verify(lic) {
		t.Error("verify() returned true for tampered license")
	}
}

func TestCheckMissingFile(t *testing.T) {
	lic, err := Check("/nonexistent/path/license.json")
	if err != nil {
		t.Errorf("Check() missing file should return nil error, got %v", err)
	}
	if lic != nil {
		t.Error("Check() missing file should return nil license")
	}
}

func TestCheckValidLicense(t *testing.T) {
	lic := &License{
		Organization: "Test Org",
		Features:     []string{FeatureAnalyze},
		IssuedAt:     time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second),
	}
	Sign(lic)

	f, err := os.CreateTemp("", "statedrift-license-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	if err := json.NewEncoder(f).Encode(lic); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	f.Close()

	got, err := Check(f.Name())
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if got == nil {
		t.Fatal("Check() returned nil license for valid file")
	}
	if got.Organization != "Test Org" {
		t.Errorf("Organization = %q, want Test Org", got.Organization)
	}
}

func TestCheckExpiredLicense(t *testing.T) {
	lic := &License{
		Organization: "Test Org",
		Features:     []string{FeatureAll},
		IssuedAt:     time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second),
		ExpiresAt:    time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second), // expired yesterday
	}
	Sign(lic)

	f, err := os.CreateTemp("", "statedrift-license-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	json.NewEncoder(f).Encode(lic)
	f.Close()

	_, err = Check(f.Name())
	if err == nil {
		t.Error("Check() expired license should return error")
	}
}

func TestHasFeature(t *testing.T) {
	lic := &License{Features: []string{FeatureAnalyze, FeatureReport}}
	if !HasFeature(lic, FeatureAnalyze) {
		t.Error("HasFeature(analyze) should be true")
	}
	if !HasFeature(lic, FeatureReport) {
		t.Error("HasFeature(report) should be true")
	}
	if HasFeature(lic, FeatureHub) {
		t.Error("HasFeature(hub) should be false")
	}
}

func TestHasFeatureAll(t *testing.T) {
	lic := &License{Features: []string{FeatureAll}}
	if !HasFeature(lic, FeatureAnalyze) {
		t.Error("'all' feature should grant analyze")
	}
	if !HasFeature(lic, FeatureHub) {
		t.Error("'all' feature should grant hub")
	}
}

func TestHasFeatureNilLicense(t *testing.T) {
	if HasFeature(nil, FeatureAnalyze) {
		t.Error("HasFeature(nil, ...) should return false")
	}
}
