// Package discover locates web roots to scan. Explicit roots win; otherwise it probes well-known
// locations for the stacks webshells live on: IIS (applicationHost.config) and Tomcat
// (CATALINA_HOME) on Windows, and Apache, Nginx and the conventional Linux webroots — because PHP,
// the most-targeted language, overwhelmingly runs on Apache/Nginx/Linux, where an IIS-and-Tomcat-only
// probe finds nothing.
//
// Reading configuration on disk is the PRIMARY method and stays that way: it is what works on a
// mounted image, a snapshot, and a host whose web server is stopped — the common IR situation, and
// the axis where this beats the incumbent's process-based approach, which cannot do it at all.
// Mechanisms that execute a server binary to dump its effective config are additive, never a
// replacement (FR-034).
//
// Every mechanism here reports an Outcome even when it finds nothing, and every path it proposes is
// validated before use. See discovery.go for why both matter.
package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// --- IIS --------------------------------------------------------------------------------------

func iisRoots(opts Options) ([]Root, []Outcome) {
	if opts.offline() {
		// applicationHost.config could be read out of a mounted Windows image, but %SystemDrive% and
		// %windir% are this host's, so the paths would be wrong in a way that is hard to notice.
		// Refusing is honest; guessing an image's Windows layout is not.
		return nil, []Outcome{liveHostOnly(MechIISConfig, opts.Root)}
	}
	if runtime.GOOS != "windows" {
		return nil, []Outcome{{
			Mechanism: MechIISConfig,
			Status:    StatusUnavailable,
			Detail:    "IIS runs on Windows only; this host is " + runtime.GOOS,
		}}
	}
	var roots []Root
	var outcomes []Outcome

	if opts.refused(MechIISDefault) {
		outcomes = append(outcomes, refusal(MechIISDefault))
	} else if d := os.Getenv("SystemDrive"); d != "" {
		roots = append(roots, Root{
			Path:      filepath.Join(d+`\`, "inetpub", "wwwroot"),
			Mechanism: MechIISDefault,
		})
		outcomes = append(outcomes, Outcome{Mechanism: MechIISDefault, Status: StatusSucceeded})
	} else {
		outcomes = append(outcomes, Outcome{
			Mechanism: MechIISDefault, Status: StatusUnavailable, Detail: "SystemDrive is not set",
		})
	}

	if opts.refused(MechIISConfig) {
		return roots, append(outcomes, refusal(MechIISConfig))
	}
	cfg := filepath.Join(os.Getenv("windir"), `System32\inetsrv\config\applicationHost.config`)
	data, _, err := readConfig(cfg)
	switch {
	case err != nil:
		outcomes = append(outcomes, Outcome{
			Mechanism: MechIISConfig, Status: StatusUnavailable,
			Detail: "applicationHost.config could not be read: " + boundedErr(err),
		})
	default:
		paths := extractPhysicalPaths(data)
		for _, p := range paths {
			roots = append(roots, Root{Path: p, Mechanism: MechIISConfig, Source: cfg})
		}
		outcomes = append(outcomes, tally(MechIISConfig, len(paths), 1,
			"applicationHost.config named no physicalPath"))
	}
	return roots, outcomes
}

// --- Tomcat -----------------------------------------------------------------------------------

// tomcatWebroots returns the webapps dir for each of CATALINA_HOME and CATALINA_BASE that is set.
// In a split install (the standard layout) both are set and differ — the apps live under
// CATALINA_BASE — so both must be scanned; assemble dedups when they coincide.
//
// Superseded for discovery by tomcat.go, which resolves each instance through its own server.xml
// instead of assuming `webapps`. Kept because it states the split-install property on its own.
func tomcatWebroots() []string {
	var roots []string
	for _, env := range []string{"CATALINA_HOME", "CATALINA_BASE"} {
		if h := os.Getenv(env); h != "" {
			roots = append(roots, filepath.Join(h, "webapps"))
		}
	}
	return roots
}

// --- Apache -----------------------------------------------------------------------------------

// apacheConfigFiles are the standard main-config and vhost locations across Linux distros and the
// common Windows Apache distributions (Apache Lounge, XAMPP). sites-enabled / conf.d holders are
// expanded by glob.
// apacheConfigPaths and nginxConfigPaths are indirected so a test can present a config tree that is
// not this host's -- which is what a mounted image is. That case is the whole reason config parsing
// is the PRIMARY method: an image has the configuration but none of the binaries, so no dump can run.
var apacheConfigPaths = apacheConfigFiles

var nginxConfigPaths = nginxConfigFiles

func apacheConfigFiles() []string {
	files := []string{
		"/etc/httpd/conf/httpd.conf",         // RHEL/CentOS/Fedora
		"/etc/apache2/apache2.conf",          // Debian/Ubuntu
		"/etc/apache2/httpd.conf",            // some SUSE
		"/usr/local/apache2/conf/httpd.conf", // source installs
		"/usr/local/etc/apache24/httpd.conf", // BSD
	}
	for _, dir := range []string{`C:\Apache24\conf\httpd.conf`, `C:\xampp\apache\conf\httpd.conf`} {
		files = append(files, dir)
	}
	// vhost drop-in directories
	for _, glob := range []string{
		"/etc/apache2/sites-enabled/*.conf",
		"/etc/httpd/conf.d/*.conf",
		"/etc/apache2/conf.d/*.conf",
	} {
		if m, err := filepath.Glob(glob); err == nil {
			files = append(files, m...)
		}
	}
	return files
}

// Go's RE2 has no backreferences, so quotes are stripped by excluding `"` from the captured path
// (opening/closing `"?` are optional and simply not captured) rather than matched as a balanced pair.
var documentRootRe = regexp.MustCompile(`(?im)^[ \t]*DocumentRoot[ \t]+"?([^"#\n\r]+?)"?[ \t]*(?:#.*)?$`)

// apacheDocumentRoots extracts every DocumentRoot from an Apache config, quoted or bare, ignoring
// commented lines and trailing comments. Multiple appear in a vhost config, one per host.
func apacheDocumentRoots(conf []byte) []string {
	var out []string
	for _, m := range documentRootRe.FindAllSubmatch(conf, -1) {
		p := strings.TrimSpace(string(m[1]))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func apacheRoots(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechApacheConfig) {
		return nil, []Outcome{refusal(MechApacheConfig)}
	}
	var roots []Root
	var notes []string
	read := 0
	for _, f := range opts.configPaths(apacheConfigPaths()) {
		data, truncated, err := readConfig(f)
		if err != nil {
			if note := configNote(f, err); note != "" {
				notes = append(notes, note)
			}
			continue
		}
		read++
		if truncated {
			notes = append(notes, fmt.Sprintf("%s exceeded %d bytes and was read only that far", f, maxConfigBytes))
		}
		for _, p := range apacheDocumentRoots(data) {
			r, ok := opts.rooted(p, MechApacheConfig, f)
			if !ok {
				notes = append(notes, fmt.Sprintf("%s named %s, which escapes the scanned filesystem", f, p))
				continue
			}
			roots = append(roots, r)
		}
	}
	if read == 0 {
		return nil, []Outcome{{
			Mechanism: MechApacheConfig, Status: StatusUnavailable,
			Detail: withNotes("no Apache configuration in the standard locations", notes),
		}}
	}
	o := tally(MechApacheConfig, len(roots), read,
		fmt.Sprintf("read %d Apache config file(s), none named a DocumentRoot", read))
	o.Detail = withNotes(o.Detail, notes)
	return roots, []Outcome{o}
}

// --- Nginx ------------------------------------------------------------------------------------

func nginxConfigFiles() []string {
	files := []string{"/etc/nginx/nginx.conf", "/usr/local/etc/nginx/nginx.conf",
		`C:\nginx\conf\nginx.conf`}
	for _, glob := range []string{
		"/etc/nginx/sites-enabled/*",
		"/etc/nginx/conf.d/*.conf",
	} {
		if m, err := filepath.Glob(glob); err == nil {
			files = append(files, m...)
		}
	}
	return files
}

// nginxRootRe matches a `root` directive (at the start of a directive, so it never catches
// *_root variants like fastcgi_temp_path), quoted or bare, up to its terminating `;`, skipping
// commented lines.
var nginxRootRe = regexp.MustCompile(`(?im)^[ \t]*root[ \t]+"?([^";#\n\r]+?)"?[ \t]*;`)

func nginxRoots(conf []byte) []string {
	var out []string
	for _, m := range nginxRootRe.FindAllSubmatch(conf, -1) {
		p := strings.TrimSpace(string(m[1]))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nginxConfigRoots(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechNginxConfig) {
		return nil, []Outcome{refusal(MechNginxConfig)}
	}
	var roots []Root
	var notes []string
	read := 0
	for _, f := range opts.configPaths(nginxConfigPaths()) {
		data, truncated, err := readConfig(f)
		if err != nil {
			if note := configNote(f, err); note != "" {
				notes = append(notes, note)
			}
			continue
		}
		read++
		if truncated {
			notes = append(notes, fmt.Sprintf("%s exceeded %d bytes and was read only that far", f, maxConfigBytes))
		}
		for _, p := range nginxRoots(data) {
			r, ok := opts.rooted(p, MechNginxConfig, f)
			if !ok {
				notes = append(notes, fmt.Sprintf("%s named %s, which escapes the scanned filesystem", f, p))
				continue
			}
			roots = append(roots, r)
		}
	}
	if read == 0 {
		return nil, []Outcome{{
			Mechanism: MechNginxConfig, Status: StatusUnavailable,
			Detail: withNotes("no Nginx configuration in the standard locations", notes),
		}}
	}
	// A glob-based read cannot follow `include` directives, which is why `nginx -T` is an additional
	// source (T082) rather than a replacement for this.
	o := tally(MechNginxConfig, len(roots), read,
		fmt.Sprintf("read %d Nginx config file(s), none named a root", read))
	o.Detail = withNotes(o.Detail, notes)
	return roots, []Outcome{o}
}

// --- Conventional locations -------------------------------------------------------------------

// linuxDefaultWebroots are the directories a distro serves from out of the box, so a bare
// drop-and-run finds a site even when no server config names an explicit root (or the config lives
// somewhere non-standard). Validation filters these to what is present.
func linuxDefaultWebroots() []string {
	return []string{
		"/var/www/html",
		"/var/www",
		"/srv/www",
		"/srv/http",
		"/usr/share/nginx/html",
	}
}

func conventionRoots(opts Options) ([]Root, []Outcome) {
	if opts.refused(MechConvention) {
		return nil, []Outcome{refusal(MechConvention)}
	}
	candidates := linuxDefaultWebroots()
	var roots []Root
	for _, p := range candidates {
		r, ok := opts.rooted(p, MechConvention, "")
		if !ok {
			continue
		}
		roots = append(roots, r)
	}
	// Status is settled by assemble, which knows which of these actually exist. Reported as
	// attempted-with-detail here so a host with none of them says so rather than staying silent —
	// a guessed root is the weakest evidence discovery produces and must never look like a
	// configured one.
	return roots, []Outcome{{
		Mechanism: MechConvention, Status: StatusAttempted,
		Detail: fmt.Sprintf("checked %d conventional location(s)", len(candidates)),
	}}
}

// --- shared helpers ---------------------------------------------------------------------------

// configPaths maps candidate configuration paths into the scanned filesystem.
//
// The candidates are written in the scanned host's namespace -- /etc/nginx/nginx.conf and friends --
// which is exactly right for the live case and needs the mount prefix for an image.
func (o Options) configPaths(candidates []string) []string {
	if !o.offline() {
		return candidates
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if mapped, ok := o.resolveUnderRoot(c); ok {
			out = append(out, mapped)
		}
	}
	return out
}

// withNotes appends config-read problems to an outcome's detail.
//
// A path that exists and is not an ordinary file is reported rather than skipped: nothing benign turns
// /etc/nginx/nginx.conf into a FIFO, so on a compromised host that is a lead. Silently skipping it
// would leave the operator with a scan that found no Nginx roots and no reason why.
func withNotes(detail string, notes []string) string {
	if len(notes) == 0 {
		return detail
	}
	joined := strings.Join(notes, "; ")
	if detail == "" {
		return joined
	}
	return detail + "; " + joined
}

func refusal(m Mechanism) Outcome {
	return Outcome{Mechanism: m, Status: StatusRefused, Detail: "refused by the operator"}
}

// tally turns "proposed N paths from M sources" into an outcome. assemble reconciles it afterwards
// against what survived validation, so succeeded here is a claim, not a conclusion.
func tally(m Mechanism, proposed, sources int, emptyDetail string) Outcome {
	if proposed == 0 {
		return Outcome{Mechanism: m, Status: StatusAttempted, Detail: emptyDetail}
	}
	return Outcome{Mechanism: m, Status: StatusSucceeded}
}

func boundedErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

var physicalPathRe = regexp.MustCompile(`physicalPath="([^"]+)"`)

// extractPhysicalPaths pulls physicalPath="..." values from applicationHost.config
// and expands %VAR% environment references.
func extractPhysicalPaths(xml []byte) []string {
	var out []string
	for _, m := range physicalPathRe.FindAllSubmatch(xml, -1) {
		out = append(out, expandWinEnv(string(m[1])))
	}
	return out
}

var winEnvRe = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)

func expandWinEnv(s string) string {
	return winEnvRe.ReplaceAllStringFunc(s, func(tok string) string {
		name := strings.Trim(tok, "%")
		if v := os.Getenv(name); v != "" {
			return v
		}
		return tok
	})
}
