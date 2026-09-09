package jvmattach

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Options configures one attach.
type Options struct {
	HostPID int
	// AgentArgs is passed to the agent's agentmain. Keep it short: the JVM's own tooling has
	// historically capped the args string, so the agent reads its real configuration from a file
	// whose path is named here.
	AgentArgs string
	// Timeout bounds the whole operation. An IR sweep must never hang against a production JVM.
	Timeout time.Duration
	// AgentJarBytes is the jar to load. Nil means the probe's own embedded agent, which is what
	// every production caller wants. The lab's positive-control carrier supplies a different jar
	// here: planting a control class must not require a webroot, a JSP engine, or a JDK.
	AgentJarBytes []byte
}

func (o Options) jarBytes() []byte {
	if len(o.AgentJarBytes) == 0 {
		return AgentJar()
	}
	return o.AgentJarBytes
}

// jarName is the staged filename for the jar actually being loaded. The digest is of THESE bytes,
// not of the embedded agent, so a custom jar cannot be staged under a name that claims to be the
// agent.
func jarName(jar []byte, nsPID int) string {
	sum := sha256.Sum256(jar)
	return fmt.Sprintf("ss-agent-%s-%d.jar", hex.EncodeToString(sum[:])[:12], nsPID)
}

// Result is what one attach produced.
type Result struct {
	Attached bool
	// NSPID is the pid inside the target's namespace, reported so an operator can correlate with
	// what they see inside a container.
	NSPID int
	// AgentCode is Agent_OnAttach's own return; 0 means the agent initialised.
	AgentCode int
	// Message carries whatever the JVM said. On JDK 21+ this is the ONLY failure evidence.
	Message string
	// Refusal, when non-empty, explains why no attach was possible. Stage 1 pairs this with its
	// external evidence so a report says "attach refused BECAUSE ..." instead of going quiet.
	Refusal string
}

// defaultTimeout matches jattach's ~6s socket wait plus room for agent initialisation.
const defaultTimeout = 20 * time.Second
