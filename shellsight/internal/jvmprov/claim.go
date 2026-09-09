// Package jvmprov verifies what a JVM CLAIMS about its own classes against what the filesystem
// actually holds.
//
// The distinction is the whole point. Everything the in-JVM agent reports is a CLAIM, because a
// sufficiently capable memshell controls the ProtectionDomain it was defined with and the
// ClassLoader that answers resource lookups. `defineClass(name, bytes, off, len, protectionDomain)`
// takes an ARBITRARY ProtectionDomain, so a shell can name `catalina.jar` as its origin and never
// look disk-absent at all. Overriding `findResource` then makes a follow-up byte comparison agree.
//
// Only an observation made from OUTSIDE the JVM is evidence. A ClassLoader cannot lie to a process
// that never asks it anything.
package jvmprov

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Claim is what the agent reported about one class. Every field is the JVM's assertion, not a
// verified fact — the type name says so deliberately.
type Claim struct {
	ClassName string
	// CodeSourceJar is the filesystem path the JVM claims backs this class, "" if it claims none.
	CodeSourceJar string
	// OutOfContract says the CodeSource is a real file OUTSIDE every repository the container
	// declares -- catalina.home/base, the classpath, java.home, -javaagent: paths, or a live
	// webapp's real path.
	//
	// Orthogonal to verification, and that is the point. Verification answers "is the JVM's claim
	// TRUE?"; this answers "is the claimed location LEGITIMATE?". A class loaded from
	// /tmp/web-install.jar -- the CISA AR25-261A shape -- is Corroborated, because the jar really
	// does exist and really does contain the class. Conflating the two questions is why that shape
	// produced no finding at any tier.
	//
	// Computed INSIDE the JVM, because only the JVM knows what its own configuration declared. The
	// agent falls open: unknown configuration yields false, never true.
	OutOfContract bool
	// DeclaredRepos renders what the class was measured against, for the evidence string.
	DeclaredRepos string
	// NestedCodeSource marks a jar:nested: URL (Spring Boot fat jars), which names an archive
	// member Go's zip reader cannot reach through one open. Reported unverifiable, not spoofed.
	NestedCodeSource bool
	// LoaderReadOK records whether the agent's OWN ClassLoader resolved bytes for this class.
	// Paired with Go's independent jar read, this is what exposes a fabricating loader.
	LoaderReadOK bool
	// Suspicion is the agent's Stage 3 rank, carried through for the report.
	Suspicion int
	// Contracts are the interfaces and superclass chain the agent observed.
	Contracts []string
	// VerifiedGenerated is the agent's structural generated-ness verdict.
	VerifiedGenerated bool
	// ClaimedDiff is the agent's own bytecode comparison result, kept as an untrusted claim.
	ClaimedDiff string
	// ProvenanceAnomaly is whatever the agent concluded, also a claim.
	ProvenanceAnomaly string
}

// DiskAbsent reports whether the JVM claims no CodeSource at all.
func (c Claim) DiskAbsent() bool { return c.CodeSourceJar == "" && !c.NestedCodeSource }

// ParseClaim reads one <n>.facts file written by the agent.
func ParseClaim(path string) (Claim, error) {
	f, err := os.Open(path)
	if err != nil {
		return Claim{}, err
	}
	defer f.Close()

	var c Claim
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		switch key {
		case "name":
			c.ClassName = val
		case "codesource":
			c.CodeSourceJar, c.NestedCodeSource = codeSourcePath(val)
		case "out_of_contract":
			c.OutOfContract = val == "true"
		case "declared_repos":
			c.DeclaredRepos = val
		case "loader_read_ok":
			c.LoaderReadOK = val == "true"
		case "verified_generated":
			c.VerifiedGenerated = val == "true"
		case "suspicion":
			c.Suspicion, _ = strconv.Atoi(val)
		case "claimed_diff":
			c.ClaimedDiff = val
		case "provenance_anomaly":
			c.ProvenanceAnomaly = val
		case "iface", "superchain", "super":
			if val != "" {
				c.Contracts = append(c.Contracts, val)
			}
		}
	}
	return c, sc.Err()
}

// codeSourcePath reduces a CodeSource URL to a filesystem path Go can open.
//
// Returns ("", false) when the JVM claims no source, and ("", true) for a nested Spring Boot jar
// URL — those name an archive member inside another archive, which is why they are reported
// unverifiable rather than mistaken for a fabricated CodeSource.
func codeSourcePath(raw string) (path string, nested bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return "", false
	}
	if strings.HasPrefix(raw, "jar:nested:") || strings.Count(raw, "!/") > 1 {
		return "", true
	}
	raw = strings.TrimPrefix(raw, "jar:")
	raw = strings.TrimPrefix(raw, "file:")
	if i := strings.Index(raw, "!/"); i >= 0 {
		raw = raw[:i]
	}
	return raw, false
}
