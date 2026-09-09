package discover

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Config dumps: asking the server for its own effective configuration.
//
// ADDITIVE, NEVER A REPLACEMENT (FR-034). Config-file parsing stays primary because it is what works
// on a mounted image, a snapshot, and a host whose web server is stopped -- the common IR situation,
// and the axis where this tool beats the incumbent's process-based approach, which cannot do it at
// all. Making the dump primary would trade the dead-box capability for `include` resolution, which is
// the narrower problem.
//
// WHAT THE DUMP BUYS, MEASURED. On an Ubuntu 25.10 host with nginx 1.28.3 and Apache 2.4.66 installed
// for the purpose, a vhost was placed in a custom include directory -- realistic, and in neither
// glob set (Apache: sites-enabled/*.conf, conf.d/*.conf; Nginx: sites-enabled/*, conf.d/*.conf):
//
//	glob parsing found     /var/www/html, /var/www/normal
//	glob parsing MISSED    /srv/hidden-apache   (in /etc/apache2/extra-vhosts/hidden.conf)
//	apache2ctl -S revealed /etc/apache2/extra-vhosts/hidden.conf, and Main DocumentRoot directly
//	nginx -T dumped        the included file's `root /srv/hidden-nginx;` inline
//
// The captured output is committed under testdata/, so the parsers stay tested on real bytes on hosts
// with no web server installed. It also closes an open question the prior-art review recorded as
// untested.
//
// THE TRADE, STATED. This executes a binary on the host, and on a compromised host that binary is
// attacker-reachable -- it may have been replaced. Both mechanisms are individually refusable
// (FR-039), and both are bounded by a timeout, because a server binary that never returns must not
// take the scan with it.

// dumpTimeout bounds one config dump.
var dumpTimeout = 10 * time.Second

// runCommand is the exec seam. A test injects captured output instead of requiring a web server.
var runCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dumpTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// stderr is dropped on purpose: `nginx -T` writes its "syntax is ok" banner there and apache2ctl
	// writes warnings. Neither is part of the answer, and both would otherwise look like failure.
	err := cmd.Run()
	return stdout.Bytes(), err
}

// lookPath is separated so a test can say "this binary is not installed" without touching PATH.
var lookPath = exec.LookPath

// --- Nginx: nginx -T ----------------------------------------------------------------------------

// nginxDumpFileRe matches the marker `nginx -T` prints before each file it dumps. Measured against
// nginx 1.28.3 output: "# configuration file /etc/nginx/nginx.conf:".
var nginxDumpFileRe = regexp.MustCompile(`(?m)^#\s*configuration file\s+(.+?):\s*$`)

// parseNginxDump attributes every `root` in a dump to the file it came from.
//
// The whole point of the dump is that it resolves `include`, so the roots it yields come from files
// the glob list never names -- and reporting them all against "nginx -T" would throw away the one
// piece of provenance an operator needs: which file to go and read.
func parseNginxDump(out []byte) []Root {
	markers := nginxDumpFileRe.FindAllSubmatchIndex(out, -1)
	if len(markers) == 0 {
		// No markers at all: not a dump we recognise. Parsing it as one anonymous blob would produce
		// roots with a fabricated source.
		return nil
	}
	var roots []Root
	for i, m := range markers {
		file := strings.TrimSpace(string(out[m[2]:m[3]]))
		end := len(out)
		if i+1 < len(markers) {
			end = markers[i+1][0]
		}
		for _, p := range nginxRoots(out[m[1]:end]) {
			roots = append(roots, Root{Path: p, Mechanism: MechNginxDump, Source: file})
		}
	}
	return roots
}

func nginxDumpRoots(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechNginxDump) {
		return nil, []Outcome{refusal(MechNginxDump)}
	}
	if opts.offline() {
		// Running this host's nginx reports this host's configuration. On a mounted image that is an
		// answer about the wrong machine, which is worse than no answer.
		return nil, []Outcome{liveHostOnly(MechNginxDump, opts.Root)}
	}
	bin, err := lookPath("nginx")
	if err != nil {
		return nil, []Outcome{{
			Mechanism: MechNginxDump, Status: StatusUnavailable,
			Detail: "nginx is not on PATH, so it cannot be asked for its effective configuration",
		}}
	}
	out, runErr := runCommand(bin, "-T")
	roots := parseNginxDump(out)
	if len(roots) == 0 {
		detail := "nginx -T produced no root directive"
		if runErr != nil {
			// An unprivileged responder is the common case: nginx -T reads files owned by root.
			detail = fmt.Sprintf("nginx -T failed (%v); config-file parsing still applies", runErr)
		}
		return nil, []Outcome{{Mechanism: MechNginxDump, Status: StatusAttempted, Detail: detail}}
	}
	o := Outcome{Mechanism: MechNginxDump, Status: StatusSucceeded}
	if runErr != nil {
		// Partial output is still worth having: a dump that failed halfway named real files first.
		o.Detail = fmt.Sprintf("nginx -T exited with %v; parsed what it produced", runErr)
	}
	return roots, []Outcome{o}
}

// --- Apache: apache2ctl -S / httpd -S -----------------------------------------------------------

// apacheDumpMainRootRe matches `Main DocumentRoot: "/var/www/html"` from a -S dump.
var apacheDumpMainRootRe = regexp.MustCompile(`(?m)^\s*Main DocumentRoot:\s*"?([^"\r\n]+?)"?\s*$`)

// apacheDumpVhostFileRe matches the `(file:line)` that -S prints for every vhost. This is what
// resolves includes: the file named here may be in no glob list at all.
var apacheDumpVhostFileRe = regexp.MustCompile(`\(([^()\r\n]+?):\d+\)`)

// apacheWrappers is the resolution order, and it is measured rather than guessed.
//
// `apache2 -S` on Debian/Ubuntu FAILS without /etc/apache2/envvars sourced. Captured from Apache
// 2.4.66 (testdata/apache2-S-no-envvars-ubuntu.txt):
//
//	AH00111: Config variable ${APACHE_RUN_DIR} is not defined
//	apache2: Syntax error on line 80 of /etc/apache2/apache2.conf: DefaultRuntimeDir must be a
//	valid directory, absolute or relative to ServerRoot
//
// apache2ctl sources envvars itself and works. So the wrapper is tried first and the raw binary is
// not tried at all: it is not a fallback, it is a known-broken invocation.
var apacheWrappers = []string{"apache2ctl", "apachectl", "httpd"}

// parseApacheDump pulls the main DocumentRoot and every config file named in the vhost table.
//
// -S does not print per-vhost DocumentRoot -- verified against real output -- so the files it names
// are read afterwards. That indirection is the feature: those paths are the includes.
func parseApacheDump(out []byte) (mainRoot string, files []string) {
	if m := apacheDumpMainRootRe.FindSubmatch(out); m != nil {
		mainRoot = strings.TrimSpace(string(m[1]))
	}
	seen := map[string]bool{}
	for _, m := range apacheDumpVhostFileRe.FindAllSubmatch(out, -1) {
		f := strings.TrimSpace(string(m[1]))
		if f == "" || seen[pathKey(f)] {
			continue
		}
		seen[pathKey(f)] = true
		files = append(files, f)
	}
	return mainRoot, files
}

func apacheDumpRoots(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechApacheDump) {
		return nil, []Outcome{refusal(MechApacheDump)}
	}
	if opts.offline() {
		return nil, []Outcome{liveHostOnly(MechApacheDump, opts.Root)}
	}
	var bin string
	for _, w := range apacheWrappers {
		if p, err := lookPath(w); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, []Outcome{{
			Mechanism: MechApacheDump, Status: StatusUnavailable,
			Detail: "none of " + strings.Join(apacheWrappers, ", ") + " is on PATH",
		}}
	}
	out, runErr := runCommand(bin, "-S")
	mainRoot, files := parseApacheDump(out)

	var roots []Root
	if mainRoot != "" {
		roots = append(roots, Root{Path: mainRoot, Mechanism: MechApacheDump, Source: bin + " -S"})
	}
	// Read the files -S named. A vhost's DocumentRoot lives in the file, not in the dump.
	//
	// Through readConfig, not os.ReadFile: these paths are attacker-influenced twice over -- an
	// intruder who can edit the Apache config chooses which paths appear in the dump, and can make one
	// of them a FIFO. Reading them unguarded would reopen the hang through a second door.
	var notes []string
	for _, f := range files {
		data, truncated, err := readConfig(f)
		if err != nil {
			if note := configNote(f, err); note != "" {
				notes = append(notes, note)
			}
			continue
		}
		if truncated {
			notes = append(notes, fmt.Sprintf("%s exceeded %d bytes and was read only that far", f, maxConfigBytes))
		}
		for _, p := range apacheDocumentRoots(data) {
			roots = append(roots, Root{Path: p, Mechanism: MechApacheDump, Source: f})
		}
	}
	if len(roots) == 0 {
		detail := fmt.Sprintf("%s -S named no DocumentRoot and no readable vhost file", filepath.Base(bin))
		if runErr != nil {
			detail = fmt.Sprintf("%s -S failed (%v); config-file parsing still applies", filepath.Base(bin), runErr)
		}
		return nil, []Outcome{{
			Mechanism: MechApacheDump, Status: StatusAttempted, Detail: withNotes(detail, notes),
		}}
	}
	o := Outcome{Mechanism: MechApacheDump, Status: StatusSucceeded}
	if runErr != nil {
		o.Detail = fmt.Sprintf("%s -S exited with %v; parsed what it produced", filepath.Base(bin), runErr)
	}
	o.Detail = withNotes(o.Detail, notes)
	return roots, []Outcome{o}
}
