package fusion

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"shellsight/internal/finding"
)

// mitreFor returns the ATT&CK technique IDs for a finding. Every webshell finding is
// T1505.003 (Web Shell); an in-memory implant that registers as an IIS module is also
// T1505.004 (IIS Components); any in-memory (reflectively/dynamically loaded) implant is
// also T1620 (Reflective Code Loading).
func mitreFor(f finding.Finding) []string {
	switch f.View {
	case "disk":
		return []string{"T1505.003"}
	case "java-mem":
		// A disk-absent class loaded via defineClass is reflective code loading.
		return []string{"T1505.003", "T1620"}
	case "dotnet-mem":
		tags := []string{"T1505.003"}
		if isIISComponent(f.Detection.Evidence) {
			tags = append(tags, "T1505.004")
		}
		tags = append(tags, "T1620") // reflectively/dynamically loaded managed module
		return tags
	case "behavioral":
		switch f.Detection.KnowledgeRef {
		case finding.KBBehaviorViewState:
			// A FAILED/keyless ViewState forge attempt — NOT a successful reflective load (a
			// valid-MAC attack leaves no 1316). Tag the web-shell attempt only, not T1620.
			return []string{"T1505.003"}
		case finding.KBBehaviorIISConfig:
			return []string{"T1505.003", "T1505.004"} // module / web.config persistence
		default: // KBBehaviorW3wpChild and any other behavioral signal
			return []string{"T1505.003"}
		}
	default:
		return nil
	}
}

// familyFingerprints maps a hardcoded crypto constant that survives into a recovered or
// decompiled webshell artifact to the family it identifies. These double as detection
// signals and as free family labels (spec §6). Keys are lower-case hex.
var familyFingerprints = map[string]string{
	"e45e329feb5d925b": "Behinder", // AES key = first 16 hex chars of MD5("rebeyond")
	"3c6e0b8a9c15224a": "Godzilla", // AES key = MD5("key")[:16] (default key)
}

// familyFromEvidence returns the family whose fingerprint constant appears in the finding's
// evidence (case-insensitive), or "" if none.
func familyFromEvidence(f finding.Finding) string {
	ev := strings.ToLower(f.Detection.Evidence)
	for constant, fam := range familyFingerprints {
		if strings.Contains(ev, constant) {
			return fam
		}
	}
	return ""
}

// iisComponentContracts are the .NET request-pipeline contract markers whose presence in a
// finding's evidence marks it an IIS Component (ATT&CK T1505.004). Matching the explicit names
// (not just the word "pipeline") keeps the tag correct even if the probe's evidence prose changes.
var iisComponentContracts = []string{
	"pipeline", "IHttpModule", "IHttpHandler", "HttpApplication", "VirtualPathProvider",
	"IRouter", "IEndpointRouteBuilder", "IStartupFilter", "IMiddleware", "IOwinMiddleware",
	"convention-middleware",
}

func isIISComponent(evidence string) bool {
	for _, c := range iisComponentContracts {
		if strings.Contains(evidence, c) {
			return true
		}
	}
	return false
}

// fingerprint is a deterministic content hash identifying "the same finding" across
// re-scans — the dedup/suppression key SIEMs and SOARs need. 16 hex chars is ample.
func fingerprint(f finding.Finding) string {
	family := ""
	if f.Classification.Family != nil {
		family = *f.Classification.Family
	}
	key := strings.Join([]string{f.Host, f.View, targetKey(f), f.Detection.Basis, f.Detection.KnowledgeRef, f.Detection.Evidence, family}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

// targetKey is the stable identity of what a finding is about.
func targetKey(f finding.Finding) string {
	if f.Target.File != nil {
		return "file:" + f.Target.File.Path
	}
	if f.Target.Process != nil {
		return fmt.Sprintf("proc:%d:%s", f.Target.Process.PID, f.Artifact.Identity)
	}
	return f.Artifact.Identity
}
