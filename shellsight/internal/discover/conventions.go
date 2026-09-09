package discover

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Conventional application-server locations (spec 007 US2; research R3; prior-art review
// the webroot-discovery prior-art review (held privately), Finding 4).
//
// The environment and the process table locate a Java server through the machine that is running it.
// A mounted image, a snapshot, or another container's /proc/<pid>/root view has neither, and until
// this table existed a Tomcat container scanned from outside ended in exit 5, "no webroot could be
// discovered" -- with the --path rescue also broken (research R1). What such a filesystem does have is
// its layout, and the layouts are documented: by the vendor for a package, by the image definition for
// a container. That documentation is the ONLY admission criterion for a row here.
//
// THE RULE FOR ADDING A ROW: a retrieved, dated primary source -- vendor documentation or the official
// image definition -- quoted in Finding 4. A tutorial is not a source. A row without one is kept as
// Blocked so the operator is TOLD the location is not checked (Constitution IV: unmeasured is a verdict,
// never a silent zero), and is never proposed.
//
// A row is a location, not a webroot. Nothing is proposed until the location confirms itself
// structurally -- Tomcat's own minimum for an instance is conf/server.xml (introduction.html), and for
// the other products it is a known deployment directory beneath the base, the same confirmation
// appserver.go already applies to a -D property. The confirmed instance then goes through the code
// that already names its directories (server.xml appBase/docBase; the appserverSpecs layouts), so this
// file adds only the step those mechanisms lacked.

// confirmKind names what proves a location is an instance.
type confirmKind int

const (
	// confirmTomcatServerXML: <location>/conf/server.xml exists. "At minimum, CATALINA_BASE must
	// contain: conf/server.xml, conf/web.xml" -- tomcat.apache.org/tomcat-10.1-doc/introduction.html.
	confirmTomcatServerXML confirmKind = iota
	// confirmDeploymentDir: one of the product's deployment directories exists beneath the location
	// (appserverSpecs, deploymentDirs).
	confirmDeploymentDir
)

// conventionSpec is one cited row.
type conventionSpec struct {
	// Product matches appserverSpecs[].Product for the non-Tomcat rows.
	Product string
	// Locations are in-FILESYSTEM globs -- the path as the scanned host names it. Under Options.Root
	// they are expanded beneath the mount; on the live host as-is.
	Locations []string
	// Citation is the short label that becomes Root.Source when no configuration file was read, and
	// names the Finding 4 row a reader should go to.
	Citation string
	Confirm  confirmKind
	// Blocked, when non-empty, is why this row is NOT checked. Reported verbatim in the mechanism's
	// outcome so the gap is visible; the locations are never proposed.
	Blocked string
}

// conventionTable is indirected so a test can present a table pointing at a temp tree (the live-host
// case) -- the same pattern as apacheConfigPaths.
var conventionTable = defaultConventions

// blockedNoCitation is the one reason a row is blocked today. Spelled once so the outcome text and the
// run-set say the same thing.
const blockedNoCitation = "no primary citation"

func defaultConventions() []conventionSpec {
	return []conventionSpec{
		// ---- Tomcat: confirmed by conf/server.xml, then resolved through tomcat.go ----
		{Product: "Tomcat", Locations: []string{"/usr/local/tomcat"},
			Citation: "official tomcat image (docker-library/docs tomcat/content.md)", Confirm: confirmTomcatServerXML},
		{Product: "Tomcat", Locations: []string{"/var/lib/tomcat[0-9]*"},
			Citation: "Debian/Ubuntu tomcat package (debian/tomcat10.service: CATALINA_BASE=/var/lib/tomcat10)", Confirm: confirmTomcatServerXML},
		{Product: "Tomcat", Locations: []string{"/opt/bitnami/tomcat"},
			Citation: "Bitnami tomcat image (bitnami/containers README)", Confirm: confirmTomcatServerXML},
		// RHEL/Fedora package: src.fedoraproject.org refused the fetch (Anubis), the Apache packaging
		// presentation is not text-extractable, the CentOS Stream mirror 404'd. Tutorials only.
		{Product: "Tomcat", Locations: []string{"/usr/share/tomcat", "/var/lib/tomcat"},
			Confirm: confirmTomcatServerXML, Blocked: blockedNoCitation},
		// Manual installs: a convention of tutorials, no vendor or image source.
		{Product: "Tomcat", Locations: []string{"/opt/tomcat"},
			Confirm: confirmTomcatServerXML, Blocked: blockedNoCitation},

		// ---- Other servers: confirmed by a deployment directory (appserver.go) ----
		{Product: "JBoss/WildFly", Locations: []string{"/opt/jboss/wildfly"},
			Citation: "official WildFly image (jboss-dockerfiles/wildfly Dockerfile: JBOSS_HOME=/opt/jboss/wildfly)", Confirm: confirmDeploymentDir},
		{Product: "JBoss/WildFly", Locations: []string{"/opt/eap"},
			Confirm: confirmDeploymentDir, Blocked: blockedNoCitation},
		{Product: "WebLogic", Locations: []string{"/u01/oracle/user_projects/domains/*"},
			Citation: "official WebLogic image (oracle/docker-images 14.1.1.0: DOMAIN_HOME=/u01/oracle/user_projects/domains/$DOMAIN_NAME)", Confirm: confirmDeploymentDir},
		{Product: "WebSphere Liberty", Locations: []string{"/opt/ibm/wlp/usr/servers/*"},
			Citation: "official websphere-liberty image (WASdev/ci.docker Dockerfile: /config -> /opt/ibm/wlp/usr/servers/defaultServer)", Confirm: confirmDeploymentDir},
		{Product: "Open Liberty", Locations: []string{"/opt/ol/wlp/usr/servers/*"},
			Citation: "official open-liberty image (Docker Hub description: installs into /opt/ol)", Confirm: confirmDeploymentDir},
		{Product: "WebSphere", Locations: []string{"/opt/IBM/WebSphere/AppServer/profiles/*"},
			Citation: "official websphere-traditional image (/opt/IBM/WebSphere/AppServer, PROFILE_NAME=AppSrv01) + IBM directory conventions (profile_root/installedApps)", Confirm: confirmDeploymentDir},
	}
}

// instance is one expanded location: where it is reachable from here, and how the scanned filesystem
// names it (empty on the live host, where the two coincide).
type instance struct {
	mapped string
	inFS   string
}

// display is the name an operator recognises: the in-filesystem form when there is one.
func (i instance) display() string {
	if i.inFS != "" {
		return i.inFS
	}
	return i.mapped
}

// expandLocation globs one in-filesystem location, beneath Options.Root when set.
func expandLocation(opts Options, glob string) []instance {
	var out []instance
	if !opts.offline() {
		matches, _ := filepath.Glob(glob)
		for _, m := range matches {
			out = append(out, instance{mapped: m})
		}
		return out
	}
	root := filepath.Clean(opts.Root)
	matches, _ := filepath.Glob(filepath.Join(root, glob))
	for _, m := range matches {
		if !withinRoot(root, m) {
			continue
		}
		rel, err := filepath.Rel(root, m)
		if err != nil {
			continue
		}
		out = append(out, instance{mapped: m, inFS: "/" + filepath.ToSlash(rel)})
	}
	return out
}

// conventionDetail is the outcome text both mechanisms emit. It always says what was checked when
// nothing was found, names a location that exists without an instance layout (a MISSED webroot, not an
// absence -- only the operator can close it with --path), and always names the rows this release does
// not check, so the gap is stated rather than implied (Constitution IV).
func conventionDetail(checked, unconfirmed []string, blocked []conventionSpec, found bool) string {
	var parts []string
	if !found {
		parts = append(parts, fmt.Sprintf("checked %d conventional location(s): %s; none held an instance",
			len(checked), strings.Join(checked, ", ")))
	}
	if len(unconfirmed) > 0 {
		parts = append(parts, "exists without an instance layout: "+strings.Join(unconfirmed, ", "))
	}
	if len(blocked) > 0 {
		var locs []string
		for _, b := range blocked {
			locs = append(locs, b.Locations...)
		}
		parts = append(parts, fmt.Sprintf("not checked in this release (%s): %s", blocked[0].Blocked, strings.Join(locs, ", ")))
	}
	return strings.Join(parts, "; ")
}

// appserverSpecByProduct finds the deployment layout for a convention row's product.
func appserverSpecByProduct(product string) (appserverSpec, bool) {
	for _, s := range appserverSpecs {
		if s.Product == product {
			return s, true
		}
	}
	return appserverSpec{}, false
}

// conventionRows returns the table's rows for one confirmation kind, split into checked and blocked.
func conventionRows(kind confirmKind) (checked, blocked []conventionSpec) {
	for _, row := range conventionTable() {
		if row.Confirm != kind {
			continue
		}
		if row.Blocked != "" {
			blocked = append(blocked, row)
			continue
		}
		checked = append(checked, row)
	}
	return checked, blocked
}
