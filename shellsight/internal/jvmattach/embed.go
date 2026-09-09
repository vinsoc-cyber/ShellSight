package jvmattach

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// agentJar is the in-JVM agent, compiled into the binary so the shipped artifact needs no sidecar
// file and no JRE. This is constraint C1 -- "self-contained binary" -- made mechanical.
//
//go:embed agent/javamem-agent.jar
var agentJar []byte

// AgentJar returns the embedded agent bytes.
func AgentJar() []byte { return agentJar }

// AgentDigest identifies the embedded agent build. It goes into the report so an analyst can tell
// which agent produced a finding, and into the staged jar's filename so two concurrent scans of one
// host cannot collide on a path.
func AgentDigest() string {
	h := sha256.Sum256(agentJar)
	return hex.EncodeToString(h[:8])
}
