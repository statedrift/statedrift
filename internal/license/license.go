// Package license verifies statedrift Pro licenses.
//
// License format: a JSON file signed for integrity. The signature covers the
// canonical JSON of the license with the sig field omitted.
//
// Free-tier behavior: a missing license file at /etc/statedrift/license.json
// is not an error — Check returns (nil, nil) and callers treat that as
// "free tier, no Pro features."
package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// licenseSecret is injected at build time via ldflags. The default below is
// a non-functional placeholder for dev builds — production releases inject a
// real value from the build environment. Do not commit the real value.
var licenseSecret = "PLACEHOLDER_DEV_BUILD_DO_NOT_SHIP"

// Feature constants for use with HasFeature.
const (
	FeatureAnalyze = "analyze" // anomaly baseline engine
	FeatureReport  = "report"  // PDF/Markdown report generation
	FeatureSIEM    = "siem"    // SIEM event export
	FeatureHub     = "hub"     // multi-host aggregation
	FeatureAll     = "all"     // grants every Pro feature
)

// License represents a statedrift Pro license.
type License struct {
	Organization string    `json:"org"`
	Features     []string  `json:"features"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Signature    string    `json:"sig,omitempty"`
}

// Check loads and verifies the license at path.
// Returns (nil, nil) when no license file exists — callers treat this as "free tier".
// Returns an error when a license file is present but invalid or expired.
func Check(path string) (*License, error) {
	if path == "" {
		path = "/etc/statedrift/license.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no license = free tier, not an error
		}
		return nil, fmt.Errorf("reading license: %w", err)
	}

	var lic License
	if err := json.Unmarshal(data, &lic); err != nil {
		return nil, fmt.Errorf("parsing license: %w", err)
	}

	if !verify(&lic) {
		return nil, fmt.Errorf("license signature invalid — file may be tampered or incorrectly issued")
	}

	if time.Now().After(lic.ExpiresAt) {
		return nil, fmt.Errorf("license expired on %s (org: %s)", lic.ExpiresAt.Format("2006-01-02"), lic.Organization)
	}

	return &lic, nil
}

// HasFeature returns true if the license grants the requested feature.
// A nil license always returns false (free tier).
func HasFeature(lic *License, feature string) bool {
	if lic == nil {
		return false
	}
	for _, f := range lic.Features {
		if f == feature || f == FeatureAll {
			return true
		}
	}
	return false
}

// Sign computes the HMAC-SHA256 signature for a license and sets its Signature field.
// Used by the license issuance tool; not needed in the agent binary.
func Sign(lic *License) {
	lic.Signature = ""
	data, _ := json.Marshal(lic)
	mac := hmac.New(sha256.New, []byte(licenseSecret))
	mac.Write(data)
	lic.Signature = hex.EncodeToString(mac.Sum(nil))
}

// verify checks the HMAC signature on a license.
func verify(lic *License) bool {
	sig := lic.Signature
	lic.Signature = ""
	data, err := json.Marshal(lic)
	lic.Signature = sig
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(licenseSecret))
	mac.Write(data)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}
