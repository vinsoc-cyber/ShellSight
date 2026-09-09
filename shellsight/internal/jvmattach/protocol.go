// Package jvmattach speaks the HotSpot dynamic attach protocol directly, with no JDK on either
// side. That is what makes a self-contained binary possible: the previous path shelled out to a
// host `java` running a 2.7 MB jar, which is an external-runtime dependency on every target.
//
// The wire format is taken from jattach/jattach@master src/posix/jattach_hotspot.c and
// src/posix/psutil.c, read rather than recalled.
package jvmattach

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// protocolVersion is the literal the JVM's AttachListener expects as the first NUL-terminated
// field. It is the protocol version, not a JDK version, and has been "1" throughout.
const protocolVersion = "1"

// wireSlots is the fixed number of NUL-terminated fields the JVM reads after the version: the
// command plus three arguments.
//
// The JVM BLOCKS until it has read all four. A short frame therefore hangs the attach rather than
// failing it, which presents as a mysterious timeout — so padding is not cosmetic.
const wireSlots = 4

// EncodeRequest builds one attach request frame.
//
// cmd is the command ("load", "properties", "jcmd", ...); args are its arguments. At most three
// argument slots exist, and anything beyond is merged into the third with spaces, matching jattach.
func EncodeRequest(cmd string, args ...string) []byte {
	slots := make([]string, 0, wireSlots)
	slots = append(slots, cmd)

	if len(args) <= wireSlots-1 {
		slots = append(slots, args...)
	} else {
		slots = append(slots, args[:wireSlots-2]...)
		slots = append(slots, strings.Join(args[wireSlots-2:], " "))
	}
	for len(slots) < wireSlots {
		slots = append(slots, "")
	}

	var buf bytes.Buffer
	buf.WriteString(protocolVersion)
	buf.WriteByte(0)
	for _, s := range slots {
		buf.WriteString(s)
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// ErrEmptyResponse means the JVM closed the socket without answering.
var ErrEmptyResponse = errors.New("jvmattach: empty response from the JVM")

// DecodeLoadResponse interprets the response to a `load` command.
//
// Three JDK generations answer differently, and conflating them is the classic bug in this
// protocol:
//
//	JDK 8    "0\n<agentcode>\n"
//	JDK 9+   "0\nreturn code: <agentcode>\n"
//	JDK 21+  "0\n<prose error>\n"   -- the command result is ALWAYS 0; failure is text
//
// So a bare 0 on line one proves nothing on a modern JDK. Anything on line two that is neither a
// number nor "return code: N" is treated as a FAILURE carrying that text, because that is the only
// reading which does not silently convert a failed attach into a reported success.
//
// Returns the agent's own result code (0 == loaded) and any message the JVM supplied.
func DecodeLoadResponse(raw []byte) (int, string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, "", ErrEmptyResponse
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	cmdResult, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		// Not even a numeric first line: whatever this is, it is not success.
		return -1, strings.TrimSpace(string(raw)), nil
	}
	if cmdResult != 0 {
		return cmdResult, strings.TrimSpace(strings.Join(lines[1:], "\n")), nil
	}

	rest := strings.TrimSpace(strings.Join(lines[1:], "\n"))
	if rest == "" {
		// No second line at all: nothing contradicts success.
		return 0, "", nil
	}
	if after, ok := strings.CutPrefix(rest, "return code: "); ok { // JDK 9+
		n, convErr := strconv.Atoi(strings.TrimSpace(strings.SplitN(after, "\n", 2)[0]))
		if convErr != nil {
			return -1, rest, nil
		}
		return n, rest, nil
	}
	if n, convErr := strconv.Atoi(strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0])); convErr == nil {
		return n, "", nil // JDK 8
	}
	// JDK 21+: prose where a code should be. That is a failure, whatever line one said.
	return -1, rest, nil
}
