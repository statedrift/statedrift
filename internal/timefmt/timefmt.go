// Package timefmt centralises display-side time formatting and human date
// parsing. Storage timestamps and the canonical JSON they live in are always
// UTC — see internal/collector and internal/store. This package exists only
// for CLI output and operator-typed dates (e.g. --since 2026-04-25), which
// users expect in their local zone.
package timefmt

import (
	"fmt"
	"time"
)

// Formatter renders timestamps in a configured location and parses
// human-typed YYYY-MM-DD dates as midnight in that same location.
type Formatter struct {
	loc *time.Location
}

// New returns a Formatter for the given IANA zone name. Special values
// "" and "UTC" select UTC; "Local" selects the host's local zone.
func New(name string) (*Formatter, error) {
	if name == "" {
		name = "UTC"
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("invalid display_tz %q: %w (expected IANA name like \"UTC\", \"Local\", or \"America/Los_Angeles\")", name, err)
	}
	return &Formatter{loc: loc}, nil
}

// MustNew is like New but panics on failure. Use only for static defaults.
func MustNew(name string) *Formatter {
	f, err := New(name)
	if err != nil {
		panic(err)
	}
	return f
}

// Location returns the formatter's configured zone.
func (f *Formatter) Location() *time.Location { return f.loc }

// RFC3339 renders t in the configured zone with the RFC3339 layout.
// In UTC the suffix is "Z"; in any other zone it is the numeric offset.
func (f *Formatter) RFC3339(t time.Time) string {
	return t.In(f.loc).Format(time.RFC3339)
}

// Short renders t as "2006-01-02 15:04:05 MST" — always with a zone
// abbreviation so a reader can tell which zone the numbers are in.
func (f *Formatter) Short(t time.Time) string {
	return t.In(f.loc).Format("2006-01-02 15:04:05 MST")
}

// Date renders just the date portion of t in the configured zone.
func (f *Formatter) Date(t time.Time) string {
	return t.In(f.loc).Format("2006-01-02")
}

// ParseDate parses YYYY-MM-DD as midnight in the configured zone. The
// returned time.Time can be compared directly against UTC-stored snapshot
// timestamps; Go's time.Time handles the offset.
func (f *Formatter) ParseDate(s string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02", s, f.loc)
}
