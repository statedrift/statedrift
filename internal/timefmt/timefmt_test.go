package timefmt

import (
	"strings"
	"testing"
	"time"
)

func TestNewDefaultsToUTC(t *testing.T) {
	f, err := New("")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if f.Location().String() != "UTC" {
		t.Errorf("default location = %s, want UTC", f.Location())
	}
}

func TestNewRejectsInvalidZone(t *testing.T) {
	_, err := New("Not/A/Real/Zone")
	if err == nil {
		t.Error("expected error for invalid zone, got nil")
	}
}

func TestRFC3339InUTC(t *testing.T) {
	f := MustNew("UTC")
	ts := time.Date(2026, 4, 25, 14, 30, 0, 0, time.UTC)
	got := f.RFC3339(ts)
	want := "2026-04-25T14:30:00Z"
	if got != want {
		t.Errorf("RFC3339 in UTC = %q, want %q", got, want)
	}
}

func TestRFC3339InLA(t *testing.T) {
	f, err := New("America/Los_Angeles")
	if err != nil {
		t.Skipf("America/Los_Angeles tzdata not installed: %v", err)
	}
	// Pick a date far from DST transitions so the offset is stable across runs.
	ts := time.Date(2026, 6, 15, 14, 30, 0, 0, time.UTC) // PDT = UTC-7
	got := f.RFC3339(ts)
	want := "2026-06-15T07:30:00-07:00"
	if got != want {
		t.Errorf("RFC3339 in LA = %q, want %q", got, want)
	}
}

func TestShortIncludesZoneAbbrev(t *testing.T) {
	f := MustNew("UTC")
	ts := time.Date(2026, 4, 25, 14, 30, 0, 0, time.UTC)
	got := f.Short(ts)
	if !strings.HasSuffix(got, " UTC") {
		t.Errorf("Short in UTC should end with \" UTC\", got %q", got)
	}
}

func TestParseDateInUTC(t *testing.T) {
	f := MustNew("UTC")
	got, err := f.ParseDate("2026-04-25")
	if err != nil {
		t.Fatalf("ParseDate: %v", err)
	}
	want := time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ParseDate UTC = %v, want %v", got, want)
	}
}

func TestParseDateInLA(t *testing.T) {
	f, err := New("America/Los_Angeles")
	if err != nil {
		t.Skipf("America/Los_Angeles tzdata not installed: %v", err)
	}
	got, err := f.ParseDate("2026-06-15") // PDT = UTC-7
	if err != nil {
		t.Fatalf("ParseDate: %v", err)
	}
	// Midnight 2026-06-15 in LA is 07:00 UTC.
	want := time.Date(2026, 6, 15, 7, 0, 0, 0, time.UTC)
	if !got.UTC().Equal(want) {
		t.Errorf("ParseDate LA in UTC = %v, want %v", got.UTC(), want)
	}
}

func TestRoundTripUTCSnapshotDisplayInLA(t *testing.T) {
	// A snapshot stored in UTC at 2026-06-15T03:00:00Z should display
	// as 2026-06-14 20:00:00 PDT in Los Angeles.
	la, err := New("America/Los_Angeles")
	if err != nil {
		t.Skipf("America/Los_Angeles tzdata not installed: %v", err)
	}
	stored := time.Date(2026, 6, 15, 3, 0, 0, 0, time.UTC)
	got := la.Short(stored)
	if !strings.HasPrefix(got, "2026-06-14 20:00:00") {
		t.Errorf("Short = %q, want prefix \"2026-06-14 20:00:00\"", got)
	}
	if !strings.Contains(got, "PDT") {
		t.Errorf("Short = %q, want zone abbrev PDT", got)
	}
}
