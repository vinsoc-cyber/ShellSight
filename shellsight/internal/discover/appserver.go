package discover

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// appserverRootsFromConvention derives deployment directories for JBoss/WildFly, WebLogic, Liberty and
// WebSphere instances at the documented conventional locations (conventions.go, spec 007 US2), live or
// under --root. The confirmation is the one appserverRoots already applies to a -D property: a known
// deployment directory must exist beneath the base. Nothing is proposed from a location that merely
// exists, and such a location is named in the outcome, because a server in a shape this list cannot
// map is a MISSED webroot that only the operator can close with --path.
func appserverRootsFromConvention(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechAppserverConvention) {
		return nil, []Outcome{refusal(MechAppserverConvention)}
	}
	checked, blocked := conventionRows(confirmDeploymentDir)
	var roots []Root
	var checkedNames, unconfirmed []string
	for _, row := range checked {
		spec, ok := appserverSpecByProduct(row.Product)
		if !ok {
			continue // a table row naming a product with no layout is a programming error, not a host fact
		}
		for _, loc := range row.Locations {
			checkedNames = append(checkedNames, loc)
			for _, inst := range expandLocation(opts, loc) {
				if fi, err := os.Stat(inst.mapped); err != nil || !fi.IsDir() {
					continue // absent: a guess that missed, silent by design
				}
				found := deploymentDirs(inst.mapped, spec)
				if len(found) == 0 {
					unconfirmed = append(unconfirmed, fmt.Sprintf("%s at %s", row.Product, inst.display()))
					continue
				}
				source := fmt.Sprintf("%s at %s (%s)", row.Product, inst.display(), row.Citation)
				for _, d := range found {
					r := Root{Path: d, Mechanism: MechAppserverConvention, Source: source}
					if inst.inFS != "" {
						if rel, err := filepath.Rel(inst.mapped, d); err == nil {
							r.InFilesystem = path.Join(inst.inFS, filepath.ToSlash(rel))
						}
					}
					roots = append(roots, r)
				}
			}
		}
	}
	status := StatusAttempted
	if len(roots) > 0 {
		status = StatusSucceeded
	}
	return roots, []Outcome{{
		Mechanism: MechAppserverConvention, Status: status,
		Detail: conventionDetail(checkedNames, unconfirmed, blocked, len(roots) > 0),
	}}
}

// JBoss/WildFly, WebLogic and WebSphere discovery (T085, FR-033).
//
// THESE ARE HEURISTICS, AND THE CODE TREATS THEM AS SUCH. The prior-art review
// (the webroot-discovery prior-art review (held privately), Finding 2)
// is explicit: the incumbent keys on -Djboss.home.dir, -Dweblogic.*, -Dserver.root, but
//
//	"These are conventional startup properties rather than documented discovery APIs, and this review
//	did not find vendor documentation presenting them as a supported inventory mechanism. Treat them
//	as heuristics with a confirmation step (does the derived path exist and contain a deployment
//	layout?), not as authoritative facts."
//
// So the confirmation step is structural rather than advisory: a server home is NEVER proposed as a
// webroot. Only a known deployment directory underneath it is, and that directory existing IS the
// confirmation. Proposing $JBOSS_HOME itself would put the whole product install into the scan --
// thousands of JARs, logs and configs -- and buy false positives and hours of I/O for it.
//
// THE FAILURE DIRECTION IS THE UNCOMFORTABLE ONE, so it is disclosed rather than hidden. The
// deployment-layout list below is finite, and unlike the containment deny-list this one fails CLOSED:
// a layout not in the list means no root is proposed, which on a real server means a missed webshell.
// That is why a base whose layout is unrecognised is reported by name in the outcome, with the
// suggestion to pass --path. A silent miss would be indistinguishable from "no application server
// here"; a disclosed one is a question the responder can answer.

// appserverSpec is one product's convention: the JVM properties that name an install, and the
// deployment directories to look for beneath it.
type appserverSpec struct {
	Product string
	// Properties are -D names, matched exactly. On a compromised host the attacker chooses the
	// command line, so a prefix match would let -Djboss.home.dir.evil name any path they like.
	Properties []string
	// Deployments are paths relative to the property's value. A `*` segment is globbed, because
	// per-server directories are named by the operator.
	Deployments []string
}

// appserverSpecs are the layouts looked for. Every entry is a convention observed in the wild, not a
// vendor-documented API -- which is exactly why nothing here is proposed without the directory
// existing.
var appserverSpecs = []appserverSpec{
	{
		Product:    "JBoss/WildFly",
		Properties: []string{"jboss.home.dir", "jboss.server.base.dir", "jboss.server.home.dir"},
		Deployments: []string{
			"standalone/deployments", // WildFly / JBoss EAP 6+ standalone
			"deployments",            // when the property already points at standalone/ or a server dir
			"domain/servers/*/data/content",
			"server/*/deploy", // JBoss AS 4-6
		},
	},
	{
		Product:    "WebLogic",
		Properties: []string{"weblogic.RootDirectory", "domain.home", "weblogic.home"},
		Deployments: []string{
			"autodeploy",      // development-mode drop directory
			"servers/*/stage", // staged deployments, one dir per managed server
			"servers/*/tmp/_WL_user",
			"applications",
		},
	},
	{
		Product: "WebSphere",
		// -Dserver.root points at a profile directory.
		Properties: []string{"server.root", "was.install.root", "user.install.root"},
		Deployments: []string{
			"installedApps", // profile-relative; each cell/app is a directory
			"installableApps",
		},
	},
	// Liberty (spec 007). No -D property names a Liberty server directory, so these rows are reached
	// only through conventions.go; the deployment directories are the documented ones -- Docker Hub
	// websphere-liberty: "an application file can be mounted in the dropins directory of this server".
	{
		Product:     "WebSphere Liberty",
		Deployments: []string{"apps", "dropins"},
	},
	{
		Product:     "Open Liberty",
		Deployments: []string{"apps", "dropins"},
	},
}

// appserverRoots derives deployment directories from running application servers.
func appserverRoots(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechAppserverProcess) {
		return nil, []Outcome{refusal(MechAppserverProcess)}
	}
	if opts.offline() {
		return nil, []Outcome{liveHostOnly(MechAppserverProcess, opts.Root)}
	}
	table := readProcessTable()
	if table.Err != nil {
		return nil, []Outcome{unavailableProcessTable(MechAppserverProcess, table.Err)}
	}

	var roots []Root
	var unrecognised []string
	stale := 0
	bases := 0
	for pid, argv := range table.ByPID {
		for _, spec := range appserverSpecs {
			for _, prop := range spec.Properties {
				base := catalinaProperty(argv, prop)
				if base == "" {
					continue
				}
				bases++
				source := fmt.Sprintf("pid %d -D%s (%s)", pid, prop, spec.Product)
				found := deploymentDirs(base, spec)
				if len(found) == 0 {
					if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
						// The property names nothing on this filesystem: a stale command line, or a
						// forged -D on a compromised host. It says nothing about where applications
						// live, and reporting it as an unrecognised layout would bury the case that
						// matters under the case that does not.
						stale++
						continue
					}
					// The install IS there and this list cannot map it. That is a MISSED webroot, not
					// an absence, and only the operator can close the gap with --path -- so it is
					// named rather than dropped.
					unrecognised = append(unrecognised,
						fmt.Sprintf("%s at %s (no known deployment directory beneath it)", spec.Product, base))
					continue
				}
				for _, d := range found {
					roots = append(roots, Root{Path: d, Mechanism: MechAppserverProcess, Source: source})
				}
			}
		}
	}

	switch {
	case len(roots) > 0:
		o := Outcome{Mechanism: MechAppserverProcess, Status: StatusSucceeded}
		if len(unrecognised) > 0 {
			o.Detail = "unrecognised layout, pass --path for: " + strings.Join(unrecognised, "; ")
		}
		return roots, []Outcome{o}
	case len(unrecognised) > 0:
		return nil, []Outcome{{
			Mechanism: MechAppserverProcess, Status: StatusAttempted,
			Detail: "an application server is running but its layout is unrecognised, pass --path for: " +
				strings.Join(unrecognised, "; "),
		}}
	default:
		detail := fmt.Sprintf("no running process declares a JBoss, WebLogic or WebSphere location (%s)",
			table.Examined())
		if stale > 0 {
			detail = fmt.Sprintf("%d application-server property value(s) named a path that does not "+
				"exist on this host (%s)", stale, table.Examined())
		}
		return nil, []Outcome{{Mechanism: MechAppserverProcess, Status: StatusAttempted, Detail: detail}}
	}
}

// deploymentDirs returns the deployment directories that actually exist under base.
//
// This IS the confirmation step. A path is only ever proposed because the layout it belongs to is
// present on disk, so a bare -D property on a command line -- which an attacker can write -- cannot
// by itself put a directory into the scan.
func deploymentDirs(base string, spec appserverSpec) []string {
	if strings.TrimSpace(base) == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			return
		}
		if key := pathKey(p); !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	for _, rel := range spec.Deployments {
		candidate := filepath.Join(base, filepath.FromSlash(rel))
		if !strings.Contains(rel, "*") {
			add(candidate)
			continue
		}
		matches, err := filepath.Glob(candidate)
		if err != nil {
			continue
		}
		for _, m := range matches {
			add(m)
		}
	}
	return out
}
