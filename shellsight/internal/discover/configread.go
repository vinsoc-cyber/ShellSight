package discover

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Reading a server configuration file that an intruder may have replaced.
//
// THE DEFECT THIS CLOSES, measured. Discovery read configuration with a bare os.ReadFile.
// cmd/diskprobe/fskind.go exists because two file kinds break exactly that call, and both were
// release-blocking for this port:
//
//	a FIFO                  os.Open blocks FOREVER, waiting for a writer
//	a symlink to /dev/zero  an unbounded read grows until the process dies (measured at 466 MB)
//
// The scanner was guarded and discovery was not, in the same process, reading paths an intruder can
// choose: /etc/nginx/nginx.conf, /etc/apache2/apache2.conf, $CATALINA_BASE/conf/server.xml. Measured
// against the real code: a FIFO in place of nginx.conf hung discovery indefinitely, /dev/zero did not
// return in 5s, and a 512 MiB config did not return in 20s — each taking the whole scan down before a
// single webroot was examined.
//
// A webshell hunt that an intruder can stop by replacing one config file with a pipe is not a webshell
// hunt.

// maxConfigBytes bounds one configuration read.
//
// 32 MiB is far past any real server config -- roughly 400,000 lines of directives -- and small enough
// that reading it is unremarkable. The bound exists for the attacker-chosen case, not the large-site
// case, and the large-site case is handled by TRUNCATING rather than refusing (see below).
const maxConfigBytes = 32 << 20

// errNotOrdinaryFile marks a config path that is not a regular file. Distinguished from a plain read
// error because on a compromised host it is a finding, not a nuisance: /etc/nginx/nginx.conf being a
// FIFO is not something that happens by accident.
var errNotOrdinaryFile = errors.New("not an ordinary file")

// readConfig reads a configuration file safely, reporting whether it had to stop early.
//
// os.Stat, not os.Open, decides the kind first — stat does not block on a FIFO where open does, so the
// hang is avoided by never opening one. It follows symlinks on purpose: `sites-enabled/*` entries are
// legitimately symlinks into `sites-available/`, so refusing links outright would break the most
// common Apache and Nginx layout there is. What matters is what the link RESOLVES to.
func readConfig(path string) (data []byte, truncated bool, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, false, err // usually just absent, which is the ordinary case
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s: %w (%s)", path, errNotOrdinaryFile, fi.Mode().Type())
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	// LimitReader with one byte of headroom, so "exactly at the bound" is distinguishable from "over".
	data, err = io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxConfigBytes {
		// TRUNCATE rather than refuse. A refusal fails toward missing a webroot, which is the one
		// direction discovery must never fail in; a truncated read still finds every root in the first
		// 32 MiB, and a directive split across the boundary yields at worst one path that validation
		// rejects and reports. Disclosed either way.
		return data[:maxConfigBytes], true, nil
	}
	return data, false, nil
}

// configNote turns a config-read problem into a line for the mechanism's outcome, or "" when the
// problem is the ordinary one of the file not being there.
//
// An absent config is not worth reporting -- most hosts do not run most servers. A config that exists
// and is the wrong KIND is worth reporting loudly, because nothing benign does that.
func configNote(path string, err error) string {
	switch {
	case err == nil || os.IsNotExist(err):
		return ""
	case errors.Is(err, errNotOrdinaryFile):
		return err.Error() + " -- refused without opening it, which is what a FIFO here would exploit"
	default:
		return fmt.Sprintf("%s: %s", path, boundedErr(err))
	}
}
