//go:build linux

package jvmattach

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Attach loads the embedded agent into the JVM at opts.HostPID.
//
// The sequence mirrors jattach/jattach@master src/posix/jattach_hotspot.c:
//
//	resolve nspid -> [socket already there? skip ahead] -> create sentinel (cwd, then tmp)
//	-> SIGQUIT -> poll for the socket -> unlink sentinel -> connect -> write -> read
//
// Everything that touches the target is bounded and reversible: one signal HotSpot already
// handles, one file we delete, one socket we close. Nothing is written into the target's heap
// except the agent it loads.
func Attach(opts Options) (Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	deadline := time.Now().Add(opts.Timeout)

	st, err := ParseStatus(fmt.Sprintf("/proc/%d/status", opts.HostPID))
	if err != nil {
		return Result{Refusal: "cannot read the target's /proc status: " + err.Error()}, err
	}
	nsPID := st.NSPID
	if nsPID == 0 {
		nsPID = opts.HostPID // kernels < 4.1 do not export NStgid
	}
	p := PathsFor(opts.HostPID, nsPID)
	res := Result{NSPID: nsPID}

	// The JVM authorises by comparing OUR effective uid to ITS OWN. Root passes; anything else
	// must match. Checking first turns a confusing protocol-level timeout into a clear answer an
	// operator can act on.
	if os.Geteuid() != 0 && os.Geteuid() != st.EUID {
		res.Refusal = fmt.Sprintf("euid mismatch: we are %d, the JVM runs as %d (run as that user or as root)",
			os.Geteuid(), st.EUID)
		return res, errors.New("jvmattach: " + res.Refusal)
	}

	if !socketExists(p.OurSocket) {
		if err := startAttachListener(p, opts.HostPID, deadline); err != nil {
			res.Refusal = err.Error()
			return res, err
		}
	}

	// Stage the agent where the JVM can open it, under a digest-suffixed name so two concurrent
	// scans of one host cannot collide.
	jar := opts.jarBytes()
	ourJar, theirJar := p.StagedJar(jarName(jar, nsPID))
	if err := os.WriteFile(ourJar, jar, 0o644); err != nil {
		res.Refusal = "cannot stage the agent into the target's filesystem: " + err.Error()
		return res, err
	}
	// Leave nothing behind.
	//
	// Safe because agentmain runs SYNCHRONOUSLY during the load command: by the time the response
	// below has been read, the agent has finished and every class it needed (including its bundled
	// ASM) is already loaded, so removing the jar cannot strand a lazy class load. If the agent
	// ever gains background work outliving agentmain, this removal has to move.
	defer os.Remove(ourJar)

	conn, err := net.DialTimeout("unix", p.OurSocket, time.Until(deadline))
	if err != nil {
		res.Refusal = "attach socket present but not connectable: " + err.Error()
		return res, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	// A JAVA agent jar is loaded through the JVM's built-in `instrument` bridge library, not as a
	// native library: load \0 instrument \0 false \0 <jar>=<options>.
	args := theirJar
	if opts.AgentArgs != "" {
		args += "=" + opts.AgentArgs
	}
	if _, err := conn.Write(EncodeRequest("load", "instrument", "false", args)); err != nil {
		res.Refusal = "writing the attach request failed: " + err.Error()
		return res, err
	}

	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		res.Refusal = "reading the attach response failed: " + err.Error()
		return res, err
	}
	code, msg, err := DecodeLoadResponse(raw)
	if err != nil {
		res.Refusal = err.Error()
		return res, err
	}
	res.AgentCode, res.Message = code, msg
	res.Attached = code == 0
	if !res.Attached {
		res.Refusal = fmt.Sprintf("the JVM refused the agent (code %d): %s", code, msg)
	}
	return res, nil
}

// socketExists reports whether path is a SOCKET specifically.
//
// A plain file with the right name is not an attach channel — and a plain file with that name is
// itself worth noticing, which is why jvmtriage.Channel reports on the path's presence separately.
func socketExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// startAttachListener performs the sentinel-and-signal dance that makes HotSpot open its socket.
func startAttachListener(p Paths, hostPID int, deadline time.Time) error {
	sentinel, err := createSentinel(p)
	if err != nil {
		return err
	}
	defer os.Remove(sentinel)

	if err := syscall.Kill(hostPID, syscall.SIGQUIT); err != nil {
		return fmt.Errorf("cannot signal the JVM: %w", err)
	}

	// jattach's schedule: sleep 20 ms, then 40 ms, ... capped at 500 ms, ~6 s total. Backing off
	// this way keeps a fast JVM fast without hammering a slow one.
	for delay := 20 * time.Millisecond; time.Now().Before(deadline); delay += 20 * time.Millisecond {
		if delay > 500*time.Millisecond {
			delay = 500 * time.Millisecond
		}
		time.Sleep(delay)
		if socketExists(p.OurSocket) {
			return nil
		}
		if syscall.Kill(hostPID, 0) != nil {
			return errors.New("the target process exited during attach")
		}
	}
	return errors.New("the JVM did not open its attach socket within the timeout " +
		"(it may be started with -XX:+DisableAttachMechanism or -XX:-EnableDynamicAgentLoading)")
}

// createSentinel writes the .attach_pid file HotSpot looks for on SIGQUIT.
//
// The cwd location is tried first, matching the reference implementation. Some mounted filesystems
// rewrite the owner of a newly created file, and the JVM refuses to trust a sentinel it does not
// see as owned by the attaching user — so ownership is verified and we fall back to the target's
// /tmp rather than waiting out a timeout that was never going to succeed.
func createSentinel(p Paths) (string, error) {
	for _, candidate := range []string{p.OurSentinelCwd, p.OurSentinelTmp} {
		f, err := os.OpenFile(candidate, os.O_CREATE|os.O_WRONLY, 0o660)
		if err != nil {
			continue
		}
		_ = f.Close()
		if fi, statErr := os.Stat(candidate); statErr == nil {
			if sys, ok := fi.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
				_ = os.Remove(candidate) // the JVM would not trust it
				continue
			}
		}
		return candidate, nil
	}
	return "", fmt.Errorf("cannot create an attach sentinel at %s or %s",
		filepath.Dir(p.OurSentinelCwd), filepath.Dir(p.OurSentinelTmp))
}
