package jvmprov

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Status is what INDEPENDENT verification concluded about one claim.
type Status int

const (
	// Corroborated: the claimed jar exists and really contains this class.
	Corroborated Status = iota
	// Spoofed: the claimed jar is missing, or is real but does not contain this class.
	Spoofed
	// DiskAbsentClaim: the JVM claimed no source. Honest, and suspicious for other reasons.
	DiskAbsentClaim
	// Unverifiable: a nested fat-jar URL, or the archive could not be read from outside.
	Unverifiable
)

func (s Status) String() string {
	switch s {
	case Corroborated:
		return "corroborated"
	case Spoofed:
		return "spoofed"
	case DiskAbsentClaim:
		return "disk-absent-claim"
	default:
		return "unverifiable"
	}
}

// Verification is the result of checking one claim against the real filesystem.
type Verification struct {
	Status Status
	Detail string
	// LoaderContradiction is set when the JVM's own ClassLoader produced bytes for a class the
	// filesystem does not back. That is a loader fabricating resources — the published
	// findResource bypass — caught by the only method that can catch it: not asking the loader.
	LoaderContradiction bool
}

// Verify checks one claim against the real filesystem.
//
// nsRoot is the target's filesystem root as THIS process sees it: "" for a same-namespace target,
// or /proc/<pid>/root for a containerised one. Without it every containerised JVM would report
// every class as spoofed, which is the kind of false positive that gets a tool switched off.
func Verify(c Claim, nsRoot string) Verification {
	if c.NestedCodeSource {
		return Verification{Status: Unverifiable,
			Detail: "CodeSource is a nested archive member; not openable from outside the JVM"}
	}
	if c.CodeSourceJar == "" {
		return Verification{Status: DiskAbsentClaim,
			Detail: "the JVM claims no CodeSource for this class"}
	}

	path := c.CodeSourceJar
	if nsRoot != "" {
		path = filepath.Join(nsRoot, strings.TrimPrefix(c.CodeSourceJar, "/"))
	}
	entry := strings.ReplaceAll(c.ClassName, ".", "/") + ".class"

	fi, err := os.Stat(path)
	if err != nil {
		return Verification{
			Status:              Spoofed,
			Detail:              fmt.Sprintf("claimed CodeSource %s does not exist on the filesystem", c.CodeSourceJar),
			LoaderContradiction: c.LoaderReadOK,
		}
	}
	if fi.IsDir() {
		// An exploded classes directory: look for the file directly.
		if _, err := os.Stat(filepath.Join(path, entry)); err == nil {
			return Verification{Status: Corroborated, Detail: "class found in the claimed exploded directory"}
		}
		return Verification{
			Status:              Spoofed,
			Detail:              fmt.Sprintf("claimed directory %s does not contain %s", c.CodeSourceJar, entry),
			LoaderContradiction: c.LoaderReadOK,
		}
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return Verification{Status: Unverifiable,
			Detail: fmt.Sprintf("claimed CodeSource %s is not a readable archive: %v", c.CodeSourceJar, err)}
	}
	defer zr.Close()

	// RELOCATED-LAYOUT FALLBACK, checked in the SAME pass so it costs no extra I/O.
	//
	// A Java agent may store its own classes under a rewritten name so that the application's
	// classloaders cannot pick them up. OpenTelemetry's javaagent does exactly this, and documents
	// why: "All Java class files have the .classdata extension (instead of just .class) - this
	// ensures that they will not be loaded by general class loaders included with the application,
	// making the javaagent internals completely isolated from the application code", with
	// "all classes and resources that are meant to be loaded by the AgentClassLoader ... placed
	// inside the inst/ directory" (docs/contributing/javaagent-structure.md).
	//
	// Measured 2026-09-03: 15,384 of 16,681 entries in opentelemetry-javaagent.jar are
	// inst/**/*.classdata, and looking only for the plain entry made four benign OTel classes
	// LIKELY-MALICIOUS at score 100 with LoaderContradiction set -- the tool reporting a loader
	// fabricating bytes when the jar genuinely holds them under a documented name.
	//
	// THIS IS NOT AN EXEMPTION. It is the same verification, completed: the class's bytes really are
	// inside the archive its CodeSource names, so the honest status is Corroborated. Nothing is
	// trusted about the agent, the path, or the class's name -- an implant still has to be present in
	// the jar it claims, which is what Corroborated has always meant.
	// See docs/measurements/2026-09-03-otel-agent-layout-fp/.
	relocated := "inst/" + strings.TrimSuffix(entry, ".class") + ".classdata"
	for _, f := range zr.File {
		if f.Name == entry {
			return Verification{Status: Corroborated, Detail: "class found in the claimed jar"}
		}
		if f.Name == relocated {
			return Verification{Status: Corroborated,
				Detail: fmt.Sprintf("class found in the claimed jar under the agent-isolated layout (%s)",
					relocated)}
		}
	}
	return Verification{
		Status: Spoofed,
		Detail: fmt.Sprintf("claimed CodeSource %s is a real archive but contains neither %s nor %s",
			c.CodeSourceJar, entry, relocated),
		LoaderContradiction: c.LoaderReadOK,
	}
}
