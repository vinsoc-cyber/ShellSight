package store

import (
	"testing"

	"shellsightconsole/internal/consoletest"
)

// This package resets the shared test schema, and so does internal/console's end-to-end test.
// `go test` runs different packages' binaries concurrently, so without this lock the two demolish
// each other's tables mid-run. See package consoletest for the measurement.
func TestMain(m *testing.M) { consoletest.Main(m) }
