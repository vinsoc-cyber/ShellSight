package discover

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Provenance and validation for discovered webroots.
//
// Prior art (the webroot-discovery prior-art review (held privately))
// found this to be a genuine gap: no OSS scanner reports HOW it found a webroot, and the incumbent's
// process-based discovery reports nothing at all. Two properties come out of that review, neither
// present in any implementation surveyed:
//
//  1. Discovery must degrade, not fail. A host where no web server is running still has a webroot on
//     disk, so every mechanism must account for itself — and "no nginx on this host" has to be
//     distinguishable from "nginx here, no roots configured". Those mean different things in an IR.
//  2. Discovery is an attack surface. Every input — config files, process command lines, server.xml —
//     is writable by someone on a compromised host, so a derived path is a PROPOSAL. It is validated
//     before it is scanned or reported, and a refusal is recorded rather than silently dropped.

// Mechanism names how a webroot was found. Reported with every root so that a directory read from
// live configuration is distinguishable from one guessed by convention (FR-036).
type Mechanism string

const (
	MechExplicit     Mechanism = "explicit"      // the operator named it
	MechIISConfig    Mechanism = "iis-config"    // physicalPath in applicationHost.config
	MechIISDefault   Mechanism = "iis-default"   // %SystemDrive%\inetpub\wwwroot
	MechApacheConfig Mechanism = "apache-config" // DocumentRoot in an Apache config
	MechNginxConfig  Mechanism = "nginx-config"  // root directive in an Nginx config
	// The dump mechanisms ask the server for its EFFECTIVE configuration, which resolves include
	// directives the glob lists cannot reach. Additive to config parsing, never a replacement
	// (FR-034), and individually refusable because they execute a host binary an intruder may have
	// replaced (FR-039).
	MechApacheDump Mechanism = "apache-dump"
	MechNginxDump  Mechanism = "nginx-dump"
	MechTomcatEnv  Mechanism = "tomcat-env" // CATALINA_BASE / CATALINA_HOME
	// MechTomcatProcess covers instances the environment does not mention: one started by systemd
	// or by another user carries -Dcatalina.base on its command line and nowhere else (FR-034a).
	MechTomcatProcess Mechanism = "tomcat-process"
	// MechTomcatServerXML is the instance answering for itself: Host appBase and Context docBase.
	// Separate from the instance lookup because it is what actually names the directories, and an
	// unreadable one is a fact about the host rather than a silent fallback to the default.
	MechTomcatServerXML Mechanism = "tomcat-server-xml"
	// MechAppserverProcess covers JBoss/WildFly, WebLogic and WebSphere. One mechanism rather than
	// three: they are the same heuristic -- a -D property on a JVM command line, confirmed by a
	// deployment directory existing on disk -- and each root's Source names the product and the
	// property it came from. Three near-identical "no such process" lines would be noise.
	MechAppserverProcess Mechanism = "appserver-process"
	// MechTomcatConvention and MechAppserverConvention locate instances by the layouts their vendor or
	// official image documents (conventions.go), confirmed structurally before anything is proposed.
	// They are what works when nothing is running -- an image, a snapshot, another container's root
	// view -- and they are guess-grade: a configuration read wins a tie, an absent location is silent.
	MechTomcatConvention    Mechanism = "tomcat-convention"
	MechAppserverConvention Mechanism = "appserver-convention"
	MechConvention          Mechanism = "convention" // a distro's out-of-the-box location
	// MechDiscovery is not a mechanism that reads anything: it is how the subsystem AS A WHOLE
	// accounts for itself when an operator turns it off. Reported so that "we were told not to look"
	// is visible in coverage and cannot be mistaken for "we looked and found nothing".
	MechDiscovery Mechanism = "discovery"
)

// Status is what one mechanism did on this host. The four values are distinct on purpose: an
// operator reading a report needs to tell "there is no nginx here" from "nginx is here and told us
// nothing" from "you told me not to ask".
type Status string

const (
	StatusSucceeded   Status = "succeeded"   // ran and produced at least one usable root
	StatusAttempted   Status = "attempted"   // ran, produced nothing usable
	StatusUnavailable Status = "unavailable" // nothing here to consult
	StatusRefused     Status = "refused"     // the operator disabled it
)

// Root is a webroot together with how it was found.
type Root struct {
	Path      string    `json:"path"`
	Mechanism Mechanism `json:"mechanism"`
	// Source is the config file or environment variable the path came from. Empty for a
	// conventional location, which by definition has no source to cite.
	Source string `json:"source,omitempty"`
	// InFilesystem is the path as the SCANNED filesystem names it, when that differs from where it is
	// reachable from here. On a mounted image the config says /var/www/html and the scanner opens
	// /mnt/image/var/www/html; an operator needs both, because the first is what the compromised host
	// was serving and the second is only where it happens to be attached right now.
	InFilesystem string `json:"in_filesystem,omitempty"`
	// AlsoFoundBy records the other mechanisms that proposed this same directory. Agreement between
	// an independent config read and a convention is worth keeping: it is the difference between one
	// weak signal and two that corroborate.
	AlsoFoundBy []Mechanism `json:"also_found_by,omitempty"`
	// Subsumes lists directories inside this one that were proposed separately. They are not scanned
	// again — this root already covers them — but they stay visible so the report does not appear to
	// have lost a root that was genuinely discovered.
	Subsumes []string `json:"subsumes,omitempty"`
}

// Outcome is one mechanism's account of itself.
type Outcome struct {
	Mechanism Mechanism `json:"mechanism"`
	Status    Status    `json:"status"`
	Roots     int       `json:"roots"`
	Detail    string    `json:"detail,omitempty"`
}

// Rejection is a proposed path that did not survive validation, kept so the refusal is auditable.
// A config naming a directory that no longer exists, or one pointing at `/`, is itself a finding
// during an incident.
type Rejection struct {
	Path      string    `json:"path"`
	Mechanism Mechanism `json:"mechanism"`
	Source    string    `json:"source,omitempty"`
	Reason    string    `json:"reason"`
}

// Result is everything discovery concluded: what to scan, what every mechanism did, and what was
// refused.
type Result struct {
	Roots    []Root    `json:"roots"`
	Outcomes []Outcome `json:"outcomes"`
	// Rejected is BOUNDED at maxReportedRejections. RejectedTotal is the true count, so a bound is
	// never a silent one.
	Rejected      []Rejection `json:"rejected,omitempty"`
	RejectedTotal int         `json:"rejected_total,omitempty"`
}

// Limits on what discovery will put in a report.
//
// Every input discovery reads is attacker-writable, so the volume is attacker-chosen too. Measured: an
// nginx.conf with 50,000 `root` directives yields 50,000 rejections, and the report renders one line
// each -- which buries every real finding under refusal noise, for the price of editing a config file.
// A single directive with a 1 MiB value lands that megabyte verbatim in the report and in report.json.
//
// Note WHAT is bounded. The REPORT is; the work is not. Capping how many proposals get evaluated would
// fail toward missing a real webroot, which is the one direction this must never fail in -- and 50,000
// proposals validate in 775ms, so there is nothing to buy there anyway. Capping how many refusals are
// RETAINED fails toward less detail, and the true count travels beside it so the bound is visible.
const (
	maxReportedRejections = 20
	maxReportedPathLen    = 512
)

// boundPath truncates a path for reporting, saying how long the original was. An attacker-chosen path
// length must not become the report's length.
func boundPath(p string) string {
	if len(p) <= maxReportedPathLen {
		return p
	}
	return fmt.Sprintf("%s... (%d bytes total)", p[:maxReportedPathLen], len(p))
}

// Paths returns the directories to scan.
func (r Result) Paths() []string {
	out := make([]string, 0, len(r.Roots))
	for _, root := range r.Roots {
		out = append(out, root.Path)
	}
	return out
}

// Options narrows discovery. The zero value discovers everything available from configuration and
// convention.
type Options struct {
	// Disabled turns discovery off entirely (FR-039). With no explicit root supplied that leaves
	// nothing to scan, which the caller must treat as a coverage failure rather than an empty
	// scan — see cmd/diskprobe/webrootgate.go.
	Disabled bool
	// Refuse names mechanisms the operator will not allow. Exec-based mechanisms belong here: on a
	// compromised host, `nginx -T` runs a binary an intruder may have replaced.
	Refuse map[Mechanism]bool
	// Root scans a filesystem mounted somewhere else -- an image, a snapshot, a recovered disk --
	// instead of this host. Configuration is read in THAT filesystem's namespace and the paths it
	// names are mapped into this one. See offlineroot.go: without it, discovery on a mounted image
	// read the analyst's own configuration and reported a clean verdict about an image it never
	// opened.
	Root string
}

func (o Options) refused(m Mechanism) bool { return o.Refuse != nil && o.Refuse[m] }

// Discover locates the webroots to scan. Explicit roots suppress discovery entirely (FR-039).
func Discover(explicit []string, opts Options) Result {
	if len(explicit) > 0 {
		proposed := make([]Root, 0, len(explicit))
		for _, p := range explicit {
			proposed = append(proposed, Root{Path: p, Mechanism: MechExplicit})
		}
		res := assembleUnder(opts.Root, proposed, []Outcome{{Mechanism: MechExplicit, Status: StatusSucceeded}})
		// FR-004 (spec 007): an operator's path that lies inside --root earns the same second form a
		// discovered root gets -- what the scanned host serves it as -- because the report is read
		// against the container's own layout, not against where the disk happens to be attached.
		if opts.offline() {
			for i := range res.Roots {
				if inFS, ok := servedAs(opts.Root, res.Roots[i].Path); ok {
					res.Roots[i].InFilesystem = inFS
				}
			}
		}
		return res
	}
	if opts.Disabled {
		return Result{Outcomes: []Outcome{{
			Mechanism: MechDiscovery,
			Status:    StatusRefused,
			Detail:    "discovery is disabled and no path was supplied",
		}}}
	}

	var proposed []Root
	var outcomes []Outcome
	// Config-file mechanisms first, then convention. Order is provenance, not precedence: assemble
	// keeps the stronger mechanism when two propose the same directory.
	for _, mech := range []func(Options) ([]Root, []Outcome){
		iisRoots, apacheRoots, apacheDumpRoots, nginxConfigRoots, nginxDumpRoots,
		tomcatRoots, appserverRoots, appserverRootsFromConvention, conventionRoots,
	} {
		roots, produced := mech(opts)
		proposed = append(proposed, roots...)
		outcomes = append(outcomes, produced...)
	}
	return assembleUnder(opts.Root, proposed, outcomes)
}

// Webroots returns the bare directories to scan, for callers that do not need provenance.
func Webroots(explicit []string) []string {
	return Discover(explicit, Options{}).Paths()
}

// assemble validates proposals, collapses duplicates and nested roots, and reconciles each
// mechanism's claim with what actually survived.
//
// Kept separate from Discover so the whole policy is testable without a host that happens to have
// the right servers installed. Every case worth asserting — a path that vanished, a config pointing
// at `/`, two mechanisms agreeing, a root inside another — is arranged here in a temp directory.
func assemble(proposed []Root, outcomes []Outcome) Result {
	return assembleUnder("", proposed, outcomes)
}

// assembleUnder is assemble for a filesystem mounted at root (Options.Root). Proposals that lie inside
// it are resolved and contained in THAT filesystem's namespace (resolveunder.go), which is what makes
// discovery under --root judge the scanned host rather than the scanning one: an absolute symlink
// inside an image, or a /proc/<pid>/root view, points at the scanned host's `/`, not at ours.
func assembleUnder(root string, proposed []Root, outcomes []Outcome) Result {
	var res Result

	// 1. Validate. A proposal that fails is recorded, not dropped.
	var kept []Root
	for _, p := range proposed {
		path, reason := validateRootUnder(p.Path, p.Mechanism, root)
		if reason != "" {
			if silentMiss(p, reason) {
				continue
			}
			// Counted always, retained up to the bound. The count is what makes the bound honest: a
			// reader sees "20 shown of 50,000" rather than a list that looks complete.
			res.RejectedTotal++
			if len(res.Rejected) < maxReportedRejections {
				res.Rejected = append(res.Rejected, Rejection{
					Path:      boundPath(cleanForReport(p.Path)),
					Mechanism: p.Mechanism,
					Source:    boundPath(p.Source),
					Reason:    reason,
				})
			}
			continue
		}
		p.Path = path
		kept = append(kept, p)
	}

	// 2. Collapse proposals naming the same directory.
	index := map[string]int{}
	var merged []Root
	for _, r := range kept {
		key := pathKey(r.Path)
		if i, ok := index[key]; ok {
			merged[i] = mergeSamePath(merged[i], r)
			continue
		}
		index[key] = len(merged)
		merged = append(merged, r)
	}

	// 3. Subsume nested roots. /var/www and /var/www/html are both discoverable on a stock Debian
	//    box; scanning both walks every file under html twice and doubles targets_scanned.
	contributors := map[Mechanism]map[string]bool{}
	credit := func(m Mechanism, path string) {
		if m == "" {
			return
		}
		if contributors[m] == nil {
			contributors[m] = map[string]bool{}
		}
		contributors[m][pathKey(path)] = true
	}
	var final []Root
	for i, r := range merged {
		if outer := enclosingIndex(merged, i); outer >= 0 {
			merged[outer].Subsumes = appendUnique(merged[outer].Subsumes, r.Path)
			// The inner root's mechanisms still contributed: they found a real directory, and it is
			// being scanned — as part of its parent. Crediting them keeps the outcome counts honest
			// without claiming the mechanism found the parent, which it did not.
			credit(r.Mechanism, merged[outer].Path)
			for _, m := range r.AlsoFoundBy {
				credit(m, merged[outer].Path)
			}
			continue
		}
		final = append(final, r)
	}
	for _, r := range final {
		credit(r.Mechanism, r.Path)
		for _, m := range r.AlsoFoundBy {
			credit(m, r.Path)
		}
	}
	res.Roots = final

	// 4. Reconcile each mechanism's claim with what survived. A mechanism whose every proposal was
	//    rejected did not succeed, and must not report a root the scanner never sees — otherwise the
	//    report contradicts itself.
	for _, o := range outcomes {
		o.Roots = len(contributors[o.Mechanism])
		switch {
		case o.Roots > 0 && o.Status != StatusRefused:
			o.Status = StatusSucceeded
		case o.Status == StatusSucceeded:
			o.Status = StatusAttempted
			if o.Detail == "" {
				o.Detail = "every path it proposed was rejected by validation"
			}
		}
		res.Outcomes = append(res.Outcomes, o)
	}
	return res
}

// mergeSamePath keeps the stronger provenance for a directory two mechanisms both proposed.
func mergeSamePath(keep, other Root) Root {
	if specificity(other.Mechanism) > specificity(keep.Mechanism) {
		keep, other = other, keep
	}
	keep.AlsoFoundBy = appendUniqueMech(keep.AlsoFoundBy, other.Mechanism)
	for _, m := range other.AlsoFoundBy {
		keep.AlsoFoundBy = appendUniqueMech(keep.AlsoFoundBy, m)
	}
	for _, s := range other.Subsumes {
		keep.Subsumes = appendUnique(keep.Subsumes, s)
	}
	return keep
}

// specificity ranks provenance strength: what the operator said beats what a config says, which
// beats a guess from a distro default.
func specificity(m Mechanism) int {
	switch m {
	case MechExplicit:
		return 3
	case MechConvention, MechIISDefault, MechTomcatConvention, MechAppserverConvention:
		return 1
	case "":
		return 0
	default:
		return 2 // read out of a real configuration
	}
}

// enclosingIndex returns the index of a root that contains roots[i], or -1.
func enclosingIndex(roots []Root, i int) int {
	for j := range roots {
		if j != i && isAncestor(roots[j].Path, roots[i].Path) {
			return j
		}
	}
	return -1
}

// isAncestor reports whether child is inside parent. A string-prefix test would be wrong:
// /var/www-old starts with /var/www and is not inside it.
func isAncestor(parent, child string) bool {
	p, c := pathKey(parent), pathKey(child)
	if p == c {
		return false
	}
	rel, err := filepath.Rel(p, c)
	if err != nil || rel == "" {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Reasons a proposal can fail that are NOT worth reporting when the proposal was only a guess.
// Named so silentMiss compares constants rather than prose that a later edit could drift away from.
const (
	reasonAbsent      = "the directory does not exist"
	reasonNotAbsolute = "the path is not absolute on this platform"
)

// silentMiss reports whether a failed proposal is too uninteresting to record.
//
// A conventional location is a guess -- /var/www/html on a host that has never run Apache, or a
// Linux default evaluated on Windows -- and a guess that misses says nothing about the host. Every
// absent convention was being reported as REFUSED, which on a stock Windows box is five alarming
// lines for the normal case.
//
// Only absence is dropped. A guess that EXISTS and fails containment is still reported: a
// /var/www/html symlinked to / is a fact about this host, whoever proposed the path.
func silentMiss(r Root, reason string) bool {
	switch r.Mechanism {
	case MechConvention, MechTomcatConvention, MechAppserverConvention:
		return reason == reasonAbsent || reason == reasonNotAbsolute
	}
	return false // something real named this path: a config file, an env var, or the operator
}

// validateRoot decides whether a proposed path may be scanned, returning the path to use or the
// reason it was refused (FR-037).
func validateRoot(path string, mech Mechanism) (string, string) {
	return validateRootUnder(path, mech, "")
}

// validateRootUnder is validateRoot for a proposal inside a filesystem mounted at root ("" = the live
// host); see assembleUnder for why the root matters.
func validateRootUnder(path string, mech Mechanism, root string) (string, string) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", "the proposed path is empty"
	}
	// The candidate lists span platforms deliberately -- linuxDefaultWebroots is consulted on Windows
	// too, and the Apache list carries both /etc/httpd and C:\Apache24 -- so a discovered candidate
	// must already be absolute for THIS platform. filepath.Abs would otherwise turn "/var/www" into
	// "C:\var\www" on Windows and report a path that never existed on any host. An operator's own
	// --path may be relative, because it is typed against the current directory on purpose.
	if mech != MechExplicit && !filepath.IsAbs(trimmed) {
		return "", reasonNotAbsolute
	}
	abs, err := filepath.Abs(filepath.Clean(trimmed))
	if err != nil {
		return "", fmt.Sprintf("the path cannot be resolved: %v", err)
	}
	// Inside a filesystem mounted at root, even EXISTENCE has to be judged after resolving in that
	// namespace: os.Stat follows an absolute link inside the image into our own filesystem and reports
	// "does not exist" for a directory the image plainly has (measured while building this: the
	// fixture's /var/www/html -> /srv/site was refused as absent on both platforms).
	if mech != MechExplicit && root != "" && withinRoot(filepath.Clean(root), abs) {
		resolved, err := evalSymlinksUnder(filepath.Clean(root), abs)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", reasonAbsent
			}
			return "", fmt.Sprintf("the directory cannot be resolved: %v", err)
		}
		fi, err := os.Stat(resolved)
		if err != nil {
			if os.IsNotExist(err) {
				return "", reasonAbsent
			}
			return "", fmt.Sprintf("the directory cannot be read: %v", err)
		}
		if !fi.IsDir() {
			return "", "the path is not a directory"
		}
		if reason := containmentReasonUnder(filepath.Clean(root), resolved); reason != "" {
			return "", reason
		}
		// The configured path is returned, not the resolved one (FR-018), as on the live host below.
		return abs, ""
	}
	fi, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", reasonAbsent
		}
		return "", fmt.Sprintf("the directory cannot be read: %v", err)
	}
	if !fi.IsDir() {
		return "", "the path is not a directory"
	}
	// The operator's own path is judged on what the kernel says about it -- it exists, it is a
	// directory, it can be read -- and is NOT canonicalised. Containment narrows DISCOVERY, not the
	// operator: FR-037 is about a path derived from attacker-writable input -- a config file, a
	// process command line -- where `root /;` turns a webroot sweep into a full-disk scan, and an
	// explicit --path is reachable by nobody on the host. Canonicalising it was never a safety check,
	// and it was a defect (spec 007, research R1): a responder scanning a container from a debug
	// container names the target through /proc/<pid>/root/..., and proc_pid_root(5) says that link
	// "is not merely a symbolic link. It provides the same view of the filesystem (including
	// namespaces and the set of per-process mounts) as the process itself". EvalSymlinks turned it
	// into the scanner's own `/`, judged a directory that exists only in the other namespace as
	// unresolvable, and the gate reported "none of the 1 requested webroot(s) exist" for a directory
	// `ls` listed (measured 2026-08-26). Worse, the refusal was INTERMITTENT: validation passed
	// whenever the same path happened to exist on the scanning host, on the wrong directory's evidence.
	if mech == MechExplicit {
		if reason := readableDir(abs); reason != "" {
			return "", reason
		}
		return abs, ""
	}
	// Containment is judged after resolution, because a symlink is the same widening attack wearing
	// a different hat: /var/www/html -> / passes every check above and then sweeps the disk. (Inside a
	// filesystem mounted at root the resolution happened above, in THAT namespace -- resolveunder.go:
	// an absolute link inside an image or a process-root view names the scanned host's `/`, not ours.)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Sprintf("the directory cannot be resolved: %v", err)
	}
	if reason := containmentReason(resolved); reason != "" {
		return "", reason
	}
	// The configured path is returned, not the resolved one: scanning the directory the operator or
	// the config actually names is what FR-018 confines us to, and the resolved form is only needed
	// to judge how wide that is.
	return abs, ""
}

// containmentReason refuses a path whose scan would not be a webroot scan at all.
//
// The concrete case: on a compromised host the config is attacker-writable, and a single `root /;`
// turns a webroot sweep into a full-disk scan — hours of I/O and a flood of false positives, on the
// host where the responder can least afford either. FR-037 forbids discovery widening the scan.
//
// The filesystem-root test is structural. The directory list below is not, and a deny list is a
// finite list: something absent from it is accepted, so this fails OPEN (scans too much) rather than
// closed (misses a webshell), which is the correct direction for a detector. It exists to catch the
// realistic mis-configurations and the cheap widening attacks, not to be exhaustive.
func containmentReason(resolved string) string {
	if filepath.Dir(resolved) == resolved {
		return "rejected by containment: the filesystem root is not a webroot"
	}
	if osDirectories()[pathKey(resolved)] {
		return "rejected by containment: " + resolved + " is an operating-system directory, not a webroot"
	}
	return ""
}

func osDirectories() map[string]bool {
	out := map[string]bool{}
	add := func(paths ...string) {
		for _, p := range paths {
			if p != "" {
				out[pathKey(filepath.Clean(p))] = true
			}
		}
	}
	// Bare parents only. /var is refused; /var/www is the point of the exercise.
	add("/etc", "/proc", "/sys", "/dev", "/boot", "/bin", "/sbin", "/lib", "/lib64",
		"/usr", "/usr/share", "/usr/local", "/var", "/run", "/root", "/home", "/opt", "/mnt", "/media")
	if runtime.GOOS == "windows" {
		add(os.Getenv("windir"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"),
			os.Getenv("ProgramData"), os.Getenv("SystemRoot"))
		if d := os.Getenv("SystemDrive"); d != "" {
			add(d+`\Users`, d+`\Windows`, d+`\Program Files`)
		}
	}
	return out
}

// pathKey normalises a path for comparison. Windows paths are case-insensitive, so C:\Web and
// c:\web are one directory and must not be scanned twice.
func pathKey(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

func cleanForReport(p string) string {
	if abs, err := filepath.Abs(filepath.Clean(strings.TrimSpace(p))); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

func appendUnique(list []string, s string) []string {
	for _, existing := range list {
		if pathKey(existing) == pathKey(s) {
			return list
		}
	}
	return append(list, s)
}

func appendUniqueMech(list []Mechanism, m Mechanism) []Mechanism {
	if m == "" {
		return list
	}
	for _, existing := range list {
		if existing == m {
			return list
		}
	}
	return append(list, m)
}
