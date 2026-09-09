package main

import "testing"

// The agent runs INSIDE the target JVM, so it writes the handoff as the JVM's user -- not as the
// probe's. os.MkdirTemp makes the directory 0700 owned by the probe, so whenever those two users
// differ the agent cannot write its .class/.facts/DONE output at all. Its writes are wrapped in
// catch(Exception ignore), so the failure is silent and the probe misreports it as a truncated
// sweep.
//
// This was invisible for the whole project's history because every java-mem measurement ran a ROOT
// JVM -- the 92-cell Tomcat corpus, the 26-cell Spring corpus, the archive runs, the platform
// sweep. tomcat:* images leave Config.User unset, so probe and JVM shared a uid and the bug needs a
// mismatch to appear. Five of the six published benign-zoo images run non-root, as production Java
// services normally do.
//
// See docs/measurements/2026-09-02-nonroot-jvm-handoff/.

func TestHandoffNeedsGivingAwayWhenTheJVMRunsAsAnotherUser(t *testing.T) {
	uid, gid, needed := handoffOwner(8983, 8983, 0)
	if !needed {
		t.Fatal("a JVM running as uid 8983 swept by root MUST have the handoff given to it, or the " +
			"agent cannot write DONE and the sweep is reported as truncated")
	}
	if uid != 8983 || gid != 8983 {
		t.Fatalf("handoffOwner = (%d, %d), want the target's own ids (8983, 8983)", uid, gid)
	}
}

func TestHandoffIsLeftAloneWhenTheUsersMatch(t *testing.T) {
	// The historical case: a root probe sweeping a root JVM. Nothing to do, and chowning anyway
	// would be a pointless syscall on the path every existing measurement takes.
	if _, _, needed := handoffOwner(0, 0, 0); needed {
		t.Fatal("root probe sweeping a root JVM needs no chown")
	}
	// And a non-root probe sweeping a JVM of its own uid -- e.g. an operator sweeping their own
	// application without privileges.
	if _, _, needed := handoffOwner(1000, 1000, 1000); needed {
		t.Fatal("matching non-root uids need no chown")
	}
}

func TestHandoffGidIsHonouredIndependentlyOfUid(t *testing.T) {
	// A JVM whose uid matches the probe but whose gid does not: the directory is 0700, so group
	// permissions never grant the agent anything and there is nothing to fix. Keyed on uid alone,
	// deliberately -- chowning on a gid difference would change ownership for no benefit.
	if _, _, needed := handoffOwner(0, 4242, 0); needed {
		t.Fatal("a gid-only difference does not stop a 0700 directory's owner from writing")
	}
	// But when the uid differs, the gid travels with it so the directory is coherent.
	uid, gid, needed := handoffOwner(107, 113, 0)
	if !needed || uid != 107 || gid != 113 {
		t.Fatalf("handoffOwner(107, 113, 0) = (%d, %d, %v), want (107, 113, true)", uid, gid, needed)
	}
}

func TestHandoffOwnerRefusesAnUnknownTargetUser(t *testing.T) {
	// ParseStatus yields a zero Status when /proc/<pid>/status is unreadable, which is exactly the
	// hidepid / restricted-namespace case. Zero would read as "root", and chowning the handoff to
	// root when the JVM is really some service account would look like a fix while changing
	// nothing -- the agent still could not write, and the sweep would still be misreported.
	//
	// So an unreadable status must NOT be treated as uid 0. The caller is expected to skip the
	// chown and let the existing attach-refused path report the uncertainty instead.
	if _, _, needed := handoffOwner(-1, -1, 0); needed {
		t.Fatal("an unknown target uid must not be chowned to; it has to be reported, not guessed")
	}
}
