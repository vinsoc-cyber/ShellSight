package perlpytaint

import "testing"

// The CGI request body is an OUT PARAMETER, and an assignment-based propagator cannot see it.
//
// RFC 3875 section 4.2: "Request data is accessed by the script in a system-defined method; unless
// defined otherwise, this will be by reading the 'standard input' file descriptor or file handle",
// bounded by CONTENT_LENGTH. In Perl that is written `read(STDIN, $buf, $ENV{'CONTENT_LENGTH'})`
// or `sysread(...)`, and in Python `sys.stdin.read(...)`. perlsec puts the channel inside the taint
// model explicitly -- "all file input" is tainted.
//
// The pass already recognised `<STDIN>`, which is the LINE-reading form, and the third argument of
// the call form is itself a recognised source (`$ENV{'CONTENT_LENGTH'}`). It still saw nothing,
// because `sysread` assigns through its SECOND argument: there is no `$x =` on the line for
// `perlAssign` to match, so the taint never enters the variable and the whole parser chain
// downstream stays clean.
//
// MEASURED before this was written, over the 24 real samples: 10 contain a body read and all 10
// also carry a source the pass already recognises -- so at FILE level the addition looked inert.
// At FLOW level it is not: TWO of the ten produce no finding at all,
// `Perl_Web_Shell_by_RST-GHC.pl` and `devilzShell.cgi`, and both use `sysread(STDIN, $query,
// $ENV{'CONTENT_LENGTH'})` feeding a hand-rolled parameter parser. See
// internal/perlpytaint/flowgap_corpus_test.go, which is the measurement.

func TestPerlBodyReadTaintsItsOutParameter(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"sysread with CONTENT_LENGTH", "#!/usr/bin/perl\n" +
			"sysread(STDIN,$query,$ENV{'CONTENT_LENGTH'});\n" +
			"system($query);\n"},
		{"read with CONTENT_LENGTH", "#!/usr/bin/perl\n" +
			"read(STDIN, $buf, $ENV{'CONTENT_LENGTH'});\n" +
			"system($buf);\n"},
		{"read into a my-declared scalar", "#!/usr/bin/perl\n" +
			"read(STDIN, my $body, $ENV{'CONTENT_LENGTH'});\n" +
			"my $out = `$body`;\n"},
		{"through the parameter-parser chain, as the real shells write it",
			"#!/usr/bin/perl\n" +
				"sysread(STDIN,$query,$ENV{'CONTENT_LENGTH'});\n" +
				"@formfields = split(/&/,$query);\n" +
				"foreach my $pair (@formfields) {\n" +
				"  ($f_n,$f_v) = split(/=/,$pair);\n" +
				"  $FORM{$f_n} = $f_v;\n" +
				"}\n" +
				"system($FORM{'cmd'});\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Analyze([]byte(tc.src), "perl"); len(got) == 0 {
				t.Fatalf("no finding; the body read is the request channel here")
			}
		})
	}
}

func TestPythonStdinBodyReadTaintsItsResult(t *testing.T) {
	src := "#!/usr/bin/python\n" +
		"import os, sys\n" +
		"n = int(os.environ['CONTENT_LENGTH'])\n" +
		"body = sys.stdin.read(n)\n" +
		"os.system(body)\n"
	if got := Analyze([]byte(src), "python"); len(got) == 0 {
		t.Fatalf("no finding; sys.stdin.read is the POST body")
	}
}

func TestABodyReadThatIsNotTheRequestDoesNotTaint(t *testing.T) {
	// The discriminator, and the reason this is not simply "STDIN is tainted". A command-line tool
	// reading an interactive answer is not a CGI program, and treating it as one cost three
	// confirmed-band false positives on webmin/bin/language-manager before perlPyLang stopped
	// analysing it. Here the same shape is tested at the taint layer: a line-at-a-time prompt with
	// no CGI framing must not taint.
	src := "#!/usr/bin/perl\n" +
		"print \"Delete everything? [y/N] \";\n" +
		"chomp(my $a = <STDIN>);\n" +
		"system(\"git add $a\") if $a eq 'y';\n"
	if got := Analyze([]byte(src), "perl"); len(got) != 0 {
		t.Fatalf("an interactive prompt is not a request channel, got %d finding(s): %+v",
			len(got), got)
	}
}

// A KNOWN OPEN GAP, recorded as a test so it is countable rather than remembered.
//
// The chain above works with an EXPLICIT loop variable. Perl also lets both the loop variable and
// split's target be implicit -- `foreach (@assign) { my ($name,$value) = split /=/; }` -- and the
// pass does not follow that, because `perlForeach` requires a named variable and `namesIn` cannot
// see a read of `$_` that is not written down.
//
// ONE real sample needs it: gh:tennc/webshell:"Backdoor Dev Shells/Source/devilzShell.cgi", which
// reads `sysread(STDIN, $_, $length);` straight into `$_` and then parses with implicit splits.
//
// NOT BUILT, deliberately. It is two features -- implicit loop binding and implicit split target --
// for one sample of 24, and `$_` is the single highest over-taint risk in the language: it is
// Perl's global default variable, so tainting it in a flow-insensitive pass taints every later sink
// that reads it. The playbook allows a gap item to be published with its digest and a reason rather
// than closed, and that is the honest disposition until the benign cost of tainting `$_` has been
// measured. Recorded in docs/measurements/2026-08-23-lang-cgi/README.md.
func TestImplicitDollarUnderscoreIsAKnownGap(t *testing.T) {
	src := "#!/usr/bin/perl\n" +
		"sysread(STDIN, $_, $ENV{'CONTENT_LENGTH'});\n" +
		"@assign = split('&', $_);\n" +
		"foreach (@assign) {\n" +
		"  my ($name, $value) = split /=/;\n" +
		"  $formlist{$name} = $value;\n" +
		"}\n" +
		"system($formlist{'cmd'});\n"
	if got := Analyze([]byte(src), "perl"); len(got) != 0 {
		t.Fatalf("this gap is CLOSED -- update langkit/cgi/gap.json and delete this test; "+
			"got %d finding(s)", len(got))
	}
}
