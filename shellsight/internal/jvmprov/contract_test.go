package jvmprov

import "testing"

// The out-of-contract fact is computed INSIDE the JVM (only the JVM knows what its own
// configuration declared), so what Go owns is the parse and the guarantee that it does not disturb
// verification. These tests pin exactly that boundary.
//
// factsFile and makeJar are the package's existing test helpers -- reused rather than duplicated so
// the handoff format has one definition in the tests too.

func TestOutOfContractIsParsed(t *testing.T) {
	c, err := ParseClaim(factsFile(t,
		"name\tcom.x.Y\ncodesource\tfile:/tmp/web-install.jar\nout_of_contract\ttrue\n"+
			"declared_repos\t4 declared repositor(ies)\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.OutOfContract {
		t.Fatal("out_of_contract true was not parsed")
	}
	if c.DeclaredRepos != "4 declared repositor(ies)" {
		t.Fatalf("declared_repos = %q", c.DeclaredRepos)
	}
}

// Absence must mean false, not unknown-treated-as-true. Every claim written by an agent build that
// predates this field omits the line, and reading that as "out of contract" would put every class
// of every older probe at the alert tier.
func TestAbsentOutOfContractIsFalse(t *testing.T) {
	c, err := ParseClaim(factsFile(t, "name\tcom.x.Y\ncodesource\tfile:/opt/app/WEB-INF/lib/a.jar\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.OutOfContract {
		t.Fatal("a claim with no out_of_contract line must not be out of contract")
	}
}

// The fact is orthogonal to verification, and this is the test that keeps it that way. A jar in
// /tmp that really does contain the class is CORROBORATED -- the claim is true. Only its location is
// wrong, and if Verify ever started reporting Spoofed for it the evidence string would be a lie.
func TestOutOfContractDoesNotChangeVerification(t *testing.T) {
	jar := makeJar(t, t.TempDir(), "com/x/Y.class")
	v := Verify(Claim{ClassName: "com.x.Y", CodeSourceJar: jar, OutOfContract: true}, "")
	if v.Status != Corroborated {
		t.Fatalf("an out-of-contract but real jar must still verify as Corroborated, got %v", v.Status)
	}
}

// A class with no CodeSource is DiskAbsent; it cannot also be out of contract, because there is no
// location to judge. The agent enforces this, and if it ever regresses the two signals would
// double-report one class under two incompatible explanations.
func TestDiskAbsentClaimIsNotAlsoOutOfContract(t *testing.T) {
	c, err := ParseClaim(factsFile(t, "name\tcom.x.Y\ncodesource\tnull\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.DiskAbsent() {
		t.Fatal("codesource null must be DiskAbsent")
	}
	if c.OutOfContract {
		t.Fatal("a disk-absent class must not be flagged out of contract")
	}
}
