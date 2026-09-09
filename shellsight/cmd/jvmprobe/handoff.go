package main

// handoffOwner decides who must own the handoff directory.
//
// WHY THIS EXISTS. The probe creates the handoff with os.MkdirTemp, which is mode 0700 owned by the
// probe. The agent then runs INSIDE the target JVM and writes <handoff>/<i>.class, <i>.facts and
// finally <handoff>/DONE as the JVM's user. When those users differ the agent cannot write anything
// at all, and because ExtractAgent wraps its writes in catch(Exception ignore) the failure is
// silent: the probe sees no DONE marker and reports a truncated in-JVM sweep, which is the one
// thing it is not.
//
// Measured 2026-09-02 on solr:9 (JVM as uid 8983, probe as root): coverage came back degraded with
// "the agent did not signal completion (no DONE marker)" and zero findings. A chown to the JVM's
// own uid fixes it. Full diagnosis in docs/measurements/2026-09-02-nonroot-jvm-handoff/.
//
// It stayed hidden for the project's whole history because every java-mem measurement ran a root
// JVM, so probe and target shared a uid and this returned "nothing to do" every time.
//
// Keyed on the UID alone. A 0700 directory grants its owner everything and its group nothing, so a
// gid-only difference changes no outcome and chowning for it would be churn. When the uid does
// differ the gid travels with it, so the directory stays coherent.
//
// A negative target id means /proc/<pid>/status could not be read -- hidepid, or a restricted
// namespace. That must NOT be treated as uid 0: chowning to root when the JVM is really a service
// account would look like a fix while changing nothing, and the sweep would still be misreported.
// The caller skips the chown and lets the refusal path say so.
func handoffOwner(targetEUID, targetEGID, selfEUID int) (uid, gid int, needed bool) {
	if targetEUID < 0 || targetEGID < 0 {
		return 0, 0, false
	}
	if targetEUID == selfEUID {
		return 0, 0, false
	}
	return targetEUID, targetEGID, true
}
