package discover

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Tomcat discovery: find the instances, then ask each instance where its applications live.
//
// The resolution chain is documented by the vendor, and the prior-art review
// (the webroot-discovery prior-art review (held privately), Finding 2)
// records it with citations:
//
//	-Dcatalina.base  ->  $BASE/conf/server.xml  ->  <Host appBase="...">  ->  $BASE/<appBase>
//	                                             ->  <Context docBase="...">
//
// appBase defaults to `webapps` and relative names resolve against $CATALINA_BASE, so a Host with no
// appBase attribute is not a dead end. This is the incumbent's method and the review's verdict was to
// reuse it, because it is correct.
//
// Reading the environment alone was not enough: an instance started by systemd or by another user has
// its location on the JVM command line and nowhere in the scanning user's environment (FR-034a). So
// bases come from BOTH, and each root records which.

// defaultAppBase is the documented default for a <Host> with no appBase attribute.
// Tomcat 10.1 config/host.html: "Default: webapps".
const defaultAppBase = "webapps"

// catalinaBase is one Tomcat instance root and how it was found.
type catalinaBase struct {
	Path      string
	Mechanism Mechanism
	Source    string
	// InFilesystem is the instance location as the SCANNED filesystem names it, set only when that
	// differs from Path (an image, a process-root view). confDir, when set, is the already-resolved
	// conf directory: Debian links /var/lib/tomcatN/conf to /etc/tomcatN, an absolute link that must
	// be followed in the scanned namespace, not ours.
	InFilesystem string
	confDir      string
}

// tomcatRoots finds every Tomcat instance and the directories it serves applications from.
func tomcatRoots(opts Options) ([]Root, []Outcome) {
	var roots []Root
	var outcomes []Outcome

	bases, envOutcome := catalinaBasesFromEnv(opts)
	outcomes = append(outcomes, envOutcome)

	procBases, procOutcome := catalinaBasesFromProcesses(opts)
	outcomes = append(outcomes, procOutcome)
	bases = append(bases, procBases...)

	// Spec 007: the layouts a vendor or an official image documents, which is all a filesystem with
	// nothing running can offer. Confirmed by conf/server.xml before it counts as an instance.
	convBases, convOutcome := catalinaBasesFromConvention(opts)
	outcomes = append(outcomes, convOutcome)
	bases = append(bases, convBases...)

	var parseNotes []string
	for _, b := range bases {
		rs, note := rootsForCatalinaBaseUnder(opts, b)
		roots = append(roots, rs...)
		if note != "" {
			parseNotes = append(parseNotes, note)
		}
	}
	// server.xml is a separate mechanism from the instance lookup: it is the thing that actually
	// names the directories, and an unreadable or malformed one is a fact about the host worth
	// reporting rather than a silent fallback to the default.
	outcomes = append(outcomes, serverXMLOutcome(len(bases), roots, parseNotes))
	return roots, outcomes
}

func serverXMLOutcome(bases int, roots []Root, notes []string) Outcome {
	o := Outcome{Mechanism: MechTomcatServerXML}
	switch {
	case bases == 0:
		o.Status = StatusUnavailable
		o.Detail = "no Tomcat instance was located, so there was no server.xml to read"
	case len(notes) > 0:
		o.Status = StatusAttempted
		o.Detail = strings.Join(notes, "; ")
	default:
		o.Status = StatusSucceeded
	}
	_ = roots // assemble reconciles the count; this only reports what reading server.xml did
	return o
}

func catalinaBasesFromEnv(opts Options) ([]catalinaBase, Outcome) {
	if opts.refused(MechTomcatEnv) {
		return nil, refusal(MechTomcatEnv)
	}
	if opts.offline() {
		return nil, liveHostOnly(MechTomcatEnv, opts.Root)
	}
	var bases []catalinaBase
	for _, env := range []string{"CATALINA_BASE", "CATALINA_HOME"} {
		if h := strings.TrimSpace(os.Getenv(env)); h != "" {
			bases = append(bases, catalinaBase{Path: h, Mechanism: MechTomcatEnv, Source: env})
		}
	}
	if len(bases) == 0 {
		return nil, Outcome{
			Mechanism: MechTomcatEnv, Status: StatusUnavailable,
			// NOT the same as "no Tomcat here", which is why process inspection exists.
			Detail: "neither CATALINA_BASE nor CATALINA_HOME is set in this environment",
		}
	}
	return bases, Outcome{Mechanism: MechTomcatEnv, Status: StatusSucceeded}
}

// rootsForCatalinaBase resolves one instance to the directories it serves from, returning a note
// when server.xml could not be used. Live-host form; the env and process mechanisms are live-only.
func rootsForCatalinaBase(b catalinaBase) ([]Root, string) {
	return rootsForCatalinaBaseUnder(Options{}, b)
}

// rootsForCatalinaBaseUnder is rootsForCatalinaBase for an instance that may live inside a filesystem
// mounted at opts.Root. Two things change there (spec 007 US2): an ABSOLUTE appBase or docBase read
// from the instance's own server.xml names a directory in the scanned filesystem and is mapped under
// the root (and dropped if it escapes it); and every root carries the path the scanned host serves it
// as. A relative value that walks out of the root is dropped for the same reason.
func rootsForCatalinaBaseUnder(opts Options, b catalinaBase) ([]Root, string) {
	confDir := b.confDir
	if confDir == "" {
		confDir = filepath.Join(b.Path, "conf")
	}
	confPath := filepath.Join(confDir, "server.xml")

	// place turns one server.xml value (or the default) into a root, in the right namespace.
	place := func(value, source string) (Root, bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			value = defaultAppBase
		}
		absolute := filepath.IsAbs(value) || strings.HasPrefix(value, "/")
		if !opts.offline() {
			return Root{Path: resolveUnder(b.Path, value), Mechanism: b.Mechanism, Source: source}, true
		}
		if absolute {
			// Named in the SCANNED filesystem: rooted maps it under the mount and records both forms.
			return opts.rooted(value, b.Mechanism, source)
		}
		mapped := filepath.Join(b.Path, value)
		if !withinRoot(filepath.Clean(opts.Root), mapped) {
			return Root{}, false // a docBase of ../../.. is attacker-writable configuration
		}
		r := Root{Path: mapped, Mechanism: b.Mechanism, Source: source}
		if b.InFilesystem != "" {
			r.InFilesystem = path.Join(b.InFilesystem, filepath.ToSlash(value))
		}
		return r, true
	}

	data, _, err := readConfig(confPath)
	if err != nil {
		// The documented default. A stopped instance, a base we cannot read, or a CATALINA_HOME that
		// is only a binary distribution all land here, and $BASE/webapps is still the right guess --
		// but it is attributed to the env var, process or convention, not to a file we never read.
		if r, ok := place(defaultAppBase, b.Source); ok {
			return []Root{r}, ""
		}
		return nil, ""
	}
	appBases, docBases, err := parseServerXML(data)
	if err != nil {
		// Report it and still fall back: a malformed server.xml on a host that is nonetheless serving
		// applications out of webapps must not make the whole instance invisible.
		note := fmt.Sprintf("%s could not be parsed (%v); assumed the default %q", confPath, err, defaultAppBase)
		if r, ok := place(defaultAppBase, b.Source); ok {
			return []Root{r}, note
		}
		return nil, note
	}
	if len(appBases) == 0 {
		appBases = []string{defaultAppBase}
	}
	var roots []Root
	for _, ab := range appBases {
		if r, ok := place(ab, confPath); ok {
			roots = append(roots, r)
		}
	}
	// A <Context docBase> names a single application, which may live entirely outside appBase --
	// the case a webapps-only scan misses completely.
	for _, db := range docBases {
		if r, ok := place(db, confPath); ok {
			roots = append(roots, r)
		}
	}
	return roots, ""
}

// catalinaBasesFromConvention locates instances at the documented conventional locations
// (conventions.go), live or under --root. A location is an instance only when conf/server.xml is
// there -- Tomcat's own minimum -- and the conf directory is resolved in the scanned namespace first,
// because Debian links it to /etc/tomcatN with an absolute target.
func catalinaBasesFromConvention(opts Options) ([]catalinaBase, Outcome) {
	if opts.refused(MechTomcatConvention) {
		return nil, refusal(MechTomcatConvention)
	}
	checked, blocked := conventionRows(confirmTomcatServerXML)
	var bases []catalinaBase
	var checkedNames, unconfirmed []string
	for _, row := range checked {
		for _, loc := range row.Locations {
			checkedNames = append(checkedNames, loc)
			for _, inst := range expandLocation(opts, loc) {
				if fi, err := os.Stat(inst.mapped); err != nil || !fi.IsDir() {
					continue // absent: a guess that missed, silent by design
				}
				confDir := filepath.Join(inst.mapped, "conf")
				if opts.offline() {
					if resolved, err := evalSymlinksUnder(filepath.Clean(opts.Root), confDir); err == nil {
						confDir = resolved
					}
				}
				if fi, err := os.Stat(filepath.Join(confDir, "server.xml")); err != nil || !fi.Mode().IsRegular() {
					unconfirmed = append(unconfirmed, inst.display())
					continue
				}
				bases = append(bases, catalinaBase{
					Path: inst.mapped, InFilesystem: inst.inFS, confDir: confDir,
					Mechanism: MechTomcatConvention, Source: row.Citation,
				})
			}
		}
	}
	status := StatusAttempted
	if len(bases) > 0 {
		status = StatusSucceeded
	}
	return bases, Outcome{
		Mechanism: MechTomcatConvention, Status: status,
		Detail: conventionDetail(checkedNames, unconfirmed, blocked, len(bases) > 0),
	}
}

// resolveUnder resolves a Tomcat path attribute. "Relative path names must be under the
// $CATALINA_BASE directory" (Tomcat 10.1 config/host.html), so a relative value is joined to the
// instance base rather than to the process's working directory.
func resolveUnder(base, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return filepath.Join(base, defaultAppBase)
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(base, value)
}

// parseServerXML pulls every Host appBase and Context docBase out of a server.xml.
//
// A real XML decoder rather than a regex: server.xml must be well-formed for Tomcat to start, and
// the decoder handles comments for free. The commented-out <Context> and <Host> examples that ship in
// the stock file would otherwise be read as real configuration, and each one would surface to the
// operator as a discovered-then-refused path -- noise manufactured out of a comment.
func parseServerXML(data []byte) (appBases, docBases []string, err error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// Stock server.xml is ASCII, but a Host name can carry accented characters and Tomcat allows any
	// encoding the declaration names. Without this the decoder rejects the file outright.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch strings.ToLower(start.Name.Local) {
		case "host":
			appBases = append(appBases, attr(start, "appBase", defaultAppBase))
		case "context":
			if v := attr(start, "docBase", ""); v != "" {
				docBases = append(docBases, v)
			}
		}
	}
	return appBases, docBases, nil
}

func attr(e xml.StartElement, name, fallback string) string {
	for _, a := range e.Attr {
		if strings.EqualFold(a.Name.Local, name) {
			if v := strings.TrimSpace(a.Value); v != "" {
				return v
			}
		}
	}
	return fallback
}

// catalinaBasesFromProcesses reads -Dcatalina.base / -Dcatalina.home off running JVMs (FR-034a).
//
// An instance started by systemd, or by another user, has its location on the command line and
// nowhere in the scanning user's environment. Config-file discovery cannot find it either, because
// there is no fixed path to look in -- a Tomcat instance can live anywhere.
//
// This DEGRADES rather than fails: the process table can be mostly invisible under hidepid=2, in a
// container namespace, or to an unprivileged responder, and an absent /proc (a mounted image) is a
// fact about the target. Config-file discovery stays primary (FR-034), so a host where this returns
// nothing is still covered.
func catalinaBasesFromProcesses(opts Options) ([]catalinaBase, Outcome) {
	if opts.refused(MechTomcatProcess) {
		return nil, refusal(MechTomcatProcess)
	}
	if opts.offline() {
		// The process table belongs to the machine doing the scanning. An image has no running
		// processes, and reporting this host's as though they were the image's would attribute a live
		// Tomcat to a disk that was never booted here.
		return nil, liveHostOnly(MechTomcatProcess, opts.Root)
	}
	table := readProcessTable()
	if table.Err != nil {
		return nil, unavailableProcessTable(MechTomcatProcess, table.Err)
	}
	bases := catalinaBasesFromCmdlines(table.ByPID)
	if len(bases) == 0 {
		return nil, Outcome{
			Mechanism: MechTomcatProcess, Status: StatusAttempted,
			Detail: fmt.Sprintf("no running process declares -Dcatalina.base or -Dcatalina.home (%s)",
				table.Examined()),
		}
	}
	return bases, Outcome{Mechanism: MechTomcatProcess, Status: StatusSucceeded}
}

// catalinaProperty extracts -Dname=value from one process command line. Exported for the
// platform-specific process readers to share, and for tests to exercise without a live JVM.
func catalinaProperty(cmdline []string, name string) string {
	prefix := "-D" + name + "="
	for _, arg := range cmdline {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(arg, prefix))
		}
	}
	return ""
}

// catalinaBasesFromCmdlines turns a set of process command lines into instance bases.
//
// catalina.base is preferred over catalina.home because the applications live under the base in a
// split install, which is the standard layout; both are recorded when they differ, since a binary
// distribution can also serve from its own webapps.
func catalinaBasesFromCmdlines(byPID map[int][]string) []catalinaBase {
	var bases []catalinaBase
	for pid, argv := range byPID {
		for _, prop := range []string{"catalina.base", "catalina.home"} {
			if v := catalinaProperty(argv, prop); v != "" {
				bases = append(bases, catalinaBase{
					Path:      v,
					Mechanism: MechTomcatProcess,
					Source:    fmt.Sprintf("pid %d -D%s", pid, prop),
				})
			}
		}
	}
	return bases
}
