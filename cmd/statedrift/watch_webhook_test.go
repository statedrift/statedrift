// Unit tests for the watch webhook delivery path and the analyze --fail-on
// severity threshold. These run in-process (no binary exec) and complement
// the CLI-level tests in cli_test.go.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/statedrift/statedrift/internal/collector"
	"github.com/statedrift/statedrift/internal/diff"
	"github.com/statedrift/statedrift/internal/rules"
)

func webhookFixture() (*collector.Snapshot, *diff.Result) {
	snap := &collector.Snapshot{
		Timestamp: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
		Host:      collector.Host{Hostname: "testhost"},
	}
	result := &diff.Result{
		Material: 1,
		Counters: 0,
		Changes: []diff.Change{
			{Section: "users", Type: "added", Key: "backdoor", NewValue: "uid=1001"},
		},
	}
	return snap, result
}

// TestPostWebhookDeliversPayload verifies the webhook POSTs a JSON body with
// the documented wire format: host, UTC timestamp, material/counter counts,
// and the change list.
func TestPostWebhookDeliversPayload(t *testing.T) {
	var body []byte
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	snap, result := webhookFixture()
	postWebhook(srv.URL, snap, result)

	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	var payload struct {
		Host      string        `json:"host"`
		Timestamp string        `json:"timestamp"`
		Material  int           `json:"material"`
		Counters  int           `json:"counters"`
		Changes   []diff.Change `json:"changes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v\n%s", err, body)
	}
	if payload.Host != "testhost" {
		t.Errorf("host = %q, want testhost", payload.Host)
	}
	// Wire format is UTC RFC3339 regardless of display_tz.
	if payload.Timestamp != "2026-07-06T12:00:00Z" {
		t.Errorf("timestamp = %q, want 2026-07-06T12:00:00Z", payload.Timestamp)
	}
	if payload.Material != 1 {
		t.Errorf("material = %d, want 1", payload.Material)
	}
	if len(payload.Changes) != 1 || payload.Changes[0].Key != "backdoor" {
		t.Errorf("changes = %+v, want the users/backdoor change", payload.Changes)
	}
}

// TestPostWebhookSurvivesServerError verifies a non-2xx response and a dead
// endpoint are reported, not fatal — one failed delivery must not kill watch.
func TestPostWebhookSurvivesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	snap, result := webhookFixture()
	postWebhook(srv.URL, snap, result) // must not panic or exit

	srv.Close()
	postWebhook(srv.URL, snap, result) // connection refused: must not panic
}

// TestSeverityRank pins the severity ordering --fail-on relies on.
func TestSeverityRank(t *testing.T) {
	order := []string{"low", "medium", "high", "critical"}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i-1]) >= severityRank(order[i]) {
			t.Errorf("severityRank(%q) should be < severityRank(%q)", order[i-1], order[i])
		}
	}
	if severityRank("bogus") != 0 || severityRank("") != 0 {
		t.Errorf("unknown severities must rank 0")
	}
}

// TestFailOnMet verifies the --fail-on threshold comparison.
func TestFailOnMet(t *testing.T) {
	findings := []rules.Finding{
		{Rule: rules.Rule{ID: "R99", Severity: "medium"}, Matches: 1},
	}
	cases := []struct {
		threshold string
		want      bool
	}{
		{"low", true},
		{"medium", true},
		{"high", false},
		{"critical", false},
	}
	for _, c := range cases {
		if got := failOnMet(findings, c.threshold); got != c.want {
			t.Errorf("failOnMet(medium finding, %q) = %v, want %v", c.threshold, got, c.want)
		}
	}
	if failOnMet(nil, "low") {
		t.Error("failOnMet with no findings must be false")
	}
}
