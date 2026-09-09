// mockprobe stands in for real probes (Plans 3-5) so the core pipeline is testable.
// Behavior chosen by argv[1]:
//   emit  -> read target-spec from stdin, print a canned []Finding JSON, exit 0
//   fail  -> print error to stderr, exit 1   (tests coverage-honesty)
//   hang  -> sleep 30s                        (tests timeout)
package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "emit":
		_, _ = io.Copy(io.Discard, os.Stdin) // consume the target-spec
		fmt.Print(`[{"schema_version":"1.0","id":"mock-1","host":"WEB01","view":"mock",` +
			`"target":{"kind":"process","process":{"pid":4924,"name":"w3wp.exe"}},` +
			`"artifact":{"kind":"dynamic-assembly","identity":"EvilMarker"},` +
			`"detection":{"basis":"structural-heuristic","allowlisted":false},` +
			`"score":40,"tier":"suspicious",` +
			`"classification":{"family":null,"capability":null,"source":null,"confidence":0},` +
			`"artifacts":{}}]`)
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "mockprobe: simulated probe failure")
		os.Exit(1)
	case "hang":
		time.Sleep(30 * time.Second)
	default:
		fmt.Fprintln(os.Stderr, "usage: mockprobe emit|fail|hang")
		os.Exit(2)
	}
}
