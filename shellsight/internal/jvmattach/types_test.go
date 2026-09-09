package jvmattach

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAgentJarBytesDefaultsToEmbeddedAgent(t *testing.T) {
	// Nil must resolve to the probe's own embedded agent, so cmd/jvmprobe and cmd/jvmattachtry
	// keep working untouched.
	if got := (Options{}).jarBytes(); len(got) == 0 || string(got) != string(AgentJar()) {
		t.Fatal("nil AgentJarBytes must fall back to the embedded agent")
	}
	custom := []byte("PK\x03\x04 not really a jar")
	if got := (Options{AgentJarBytes: custom}).jarBytes(); string(got) != string(custom) {
		t.Fatalf("AgentJarBytes must be honoured, got %q", got)
	}
}

func TestStagedJarNameFollowsTheJarActuallyLoaded(t *testing.T) {
	// The staged name carries a digest so concurrent scans cannot collide. A custom jar must get
	// its OWN digest -- reusing the embedded agent's would stage different bytes under a name that
	// claims to be the agent, and the second writer would win silently.
	custom := []byte("PK\x03\x04 not really a jar")
	sum := sha256.Sum256(custom)
	want := hex.EncodeToString(sum[:])[:12]
	got := jarName(custom, 4242)
	if !strings.Contains(got, want) {
		t.Fatalf("jarName(%q) = %q, want it to contain the custom jar's digest %q", custom, got, want)
	}
	if jarName(AgentJar(), 4242) == got {
		t.Fatal("a custom jar and the embedded agent must not stage under the same name")
	}
}
