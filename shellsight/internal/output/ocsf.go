package output

import (
	"encoding/json"
	"strconv"
	"time"

	"shellsight/internal/finding"
)

// OCSF Detection Finding (class_uid 2004). We emit the operationally load-bearing subset
// that SIEMs key on (Splunk/Elastic ingest by class_uid + the core fields). Pinned to OCSF
// 1.8.0, which (unlike 1.7) does NOT require the cloud/osint field sets — so this on-prem
// host-tool subset is schema-compliant for 1.8.
const (
	ocsfVersion     = "1.8.0"
	ocsfClassUID    = 2004 // Detection Finding
	ocsfCategoryUID = 2    // Findings
	ocsfActivityID  = 1    // Create
	ocsfTypeUID     = ocsfClassUID*100 + ocsfActivityID
	ocsfStatusNew   = 1
)

type ocsfObservable struct {
	Name   string `json:"name"`
	TypeID int    `json:"type_id"`
	Value  string `json:"value,omitempty"`
}
type ocsfTechnique struct {
	UID string `json:"uid"`
}
type ocsfTactic struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
}
type ocsfAttack struct {
	Technique ocsfTechnique `json:"technique"`
	Tactic    ocsfTactic    `json:"tactic"`
	Version   string        `json:"version"`
}
type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}
type ocsfMetadata struct {
	Version string      `json:"version"`
	Product ocsfProduct `json:"product"`
}
type ocsfFindingInfo struct {
	UID   string   `json:"uid"`
	Title string   `json:"title"`
	Types []string `json:"types,omitempty"`
}
type ocsfDetectionFinding struct {
	ActivityID   int              `json:"activity_id"`
	CategoryUID  int              `json:"category_uid"`
	ClassUID     int              `json:"class_uid"`
	TypeUID      int              `json:"type_uid"`
	Time         int64            `json:"time"`
	SeverityID   int              `json:"severity_id"`
	ConfidenceID int              `json:"confidence_id"`
	StatusID     int              `json:"status_id"`
	Message      string           `json:"message"`
	Metadata     ocsfMetadata     `json:"metadata"`
	FindingInfo  ocsfFindingInfo  `json:"finding_info"`
	Observables  []ocsfObservable `json:"observables,omitempty"`
	Attacks      []ocsfAttack     `json:"attacks,omitempty"`
	Unmapped     map[string]any   `json:"unmapped,omitempty"` // ShellSight-native fields preserved
}

// sevConf maps a ShellSight tier to OCSF severity_id + confidence_id (two orthogonal enums).
func sevConf(t finding.Tier) (int, int) {
	switch t {
	case finding.TierConfirmed:
		return 5, 3 // Critical / High
	case finding.TierLikely:
		return 4, 3 // High / High
	case finding.TierSuspicious:
		return 3, 2 // Medium / Medium
	default:
		return 1, 1 // Informational / Low
	}
}

func tacticFor(techID string) ocsfTactic {
	if techID == "T1620" {
		return ocsfTactic{UID: "TA0005", Name: "Defense Evasion"} // Reflective Code Loading
	}
	// T1505.* are all Persistence (TA0003).
	return ocsfTactic{UID: "TA0003", Name: "Persistence"}
}

func attacksFor(mitre []string) []ocsfAttack {
	var out []ocsfAttack
	for _, id := range mitre {
		out = append(out, ocsfAttack{Technique: ocsfTechnique{UID: id}, Tactic: tacticFor(id), Version: "14"})
	}
	return out
}

func observablesFor(f finding.Finding) []ocsfObservable {
	obs := []ocsfObservable{{Name: "device.hostname", TypeID: 1, Value: f.Host}}
	if f.Target.File != nil {
		obs = append(obs, ocsfObservable{Name: "file.name", TypeID: 7, Value: f.Target.File.Path})
		if f.Target.File.SHA256 != "" {
			obs = append(obs, ocsfObservable{Name: "file.hash", TypeID: 8, Value: f.Target.File.SHA256})
		}
	}
	if f.Target.Process != nil {
		obs = append(obs, ocsfObservable{Name: "process.name", TypeID: 9, Value: f.Target.Process.Name})
		obs = append(obs, ocsfObservable{Name: "process.pid", TypeID: 15, Value: strconv.Itoa(f.Target.Process.PID)})
	}
	return obs
}

func ocsfFrom(rep finding.Report, f finding.Finding) ocsfDetectionFinding {
	sev, conf := sevConf(f.Tier)
	t, err := time.Parse(time.RFC3339, rep.Scan.Started)
	if err != nil {
		t = time.Unix(0, 0).UTC() // guard: never emit a year-0001 negative timestamp
	}
	uid := f.Fingerprint
	if uid == "" {
		uid = f.ID
	}
	unmapped := map[string]any{
		"shellsight_tier":  string(f.Tier),
		"shellsight_view":  f.View,
		"shellsight_score": f.Score,
		"correlation_id":   f.CorrelationID,
		"detection_basis":  f.Detection.Basis,
		"knowledge_ref":    f.Detection.KnowledgeRef,
		"scan_incomplete":  rep.Verdict.Incomplete,
	}
	if familyLabel := f.Classification.Family; familyLabel != nil {
		unmapped["family"] = *familyLabel
	}
	if author := f.Context["rule_author"]; author != "" {
		unmapped["rule_author"] = author // DRL-1.1 attribution-on-match
	}
	return ocsfDetectionFinding{
		ActivityID: ocsfActivityID, CategoryUID: ocsfCategoryUID, ClassUID: ocsfClassUID, TypeUID: ocsfTypeUID,
		Time:         t.UnixMilli(),
		SeverityID:   sev,
		ConfidenceID: conf,
		StatusID:     ocsfStatusNew,
		Message:      f.Detection.Evidence,
		Metadata:     ocsfMetadata{Version: ocsfVersion, Product: ocsfProduct{Name: "ShellSight", VendorName: "ShellSight", Version: rep.Scan.ToolVersion}},
		FindingInfo:  ocsfFindingInfo{UID: uid, Title: f.View + ": " + f.Artifact.Identity, Types: []string{f.View + "/" + f.Detection.Basis}},
		Observables:  observablesFor(f),
		Attacks:      attacksFor(f.Mitre),
		Unmapped:     unmapped,
	}
}

// ocsfLines renders each finding as a single compact JSON line (NDJSON).
func ocsfLines(rep finding.Report) []string {
	lines := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		b, err := json.Marshal(ocsfFrom(rep, f))
		if err != nil {
			continue
		}
		lines = append(lines, string(b))
	}
	return lines
}
