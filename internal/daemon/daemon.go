// Package daemon provides helpers for the statedrift daemon command.
package daemon

import (
	"fmt"
	"time"
)

// ParseInterval parses a duration string (e.g. "1h", "15m", "30s").
// Returns an error if the string is invalid, zero, or negative.
func ParseInterval(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("interval is empty")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid interval %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("interval must be positive, got %v", d)
	}
	return d, nil
}

// SystemdUnit returns the content of a systemd service unit file for the statedrift daemon.
// binaryPath is the absolute path to the statedrift binary.
// storePath is the snapshot store directory (used as STATEDRIFT_STORE env var in the unit).
// interval, if non-empty, is passed as --interval to the daemon ExecStart line.
func SystemdUnit(binaryPath, storePath, interval string) string {
	execStart := binaryPath + " daemon"
	if interval != "" {
		execStart += " --interval " + interval
	}
	return fmt.Sprintf(`[Unit]
Description=statedrift infrastructure snapshot agent
Documentation=https://github.com/statedrift/statedrift
After=network.target

[Service]
Type=simple
ExecStart=%s
Environment="STATEDRIFT_STORE=%s"
Restart=on-failure
RestartSec=30s
User=root

[Install]
WantedBy=multi-user.target
`, execStart, storePath)
}
