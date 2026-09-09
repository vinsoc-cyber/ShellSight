// Package rules holds the console's rule library: authoring, layer permissions, revisions, and
// the compile check that is the only thing standing between a typo and a team-wide outage.
//
// WHY THE COMPILE CHECK IS NOT OPTIONAL. Measured 2026-08-30 on this tree: `yr compile` over a
// directory holding 56 valid rules and one malformed rule exits 1 and writes NO output file. There
// is no partial-success mode. A malformed rule that reaches a freeze therefore blocks every agent
// build for every analyst until somebody finds it -- so the check protects the team, and expresses
// no opinion about whether a rule is any good.
package rules

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Compiler struct{ yr string }

// NewCompiler binds a compiler to one `yr` binary. It must be the `yr` from the release the rule
// set will be stamped into: a .yarc is bound to its yara-x version, and compiling with a different
// engine than the agent scans with is a silent failure class.
func NewCompiler(yrPath string) *Compiler { return &Compiler{yr: yrPath} }

// CheckRule compiles one rule TOGETHER WITH the rules it references. Fast feedback while the
// analyst can still fix it.
//
// WHY CONTEXT IS NOT OPTIONAL. YARA lets a condition name another rule, and compiling such a rule
// alone fails with `unknown identifier` even though the rule is perfectly valid. Measured over the
// shipped packs (docs/measurements/2026-08-30-yarc-parity/ C5): 50 of 5,872 rules reference another
// rule, and 16 of the first 400 split out of the YARA-Forge pack fail to compile in isolation. A
// console that checked rules one at a time would reject all of them and could not import the packs
// at all.
//
// `context` maps identifier -> rule text for the edited rule's transitive dependencies, resolved by
// internal/console/deps. Passing nil checks the rule alone, which is correct only for a rule that
// references nothing.
func (c *Compiler) CheckRule(text string, context map[string]string) error {
	dir, err := os.MkdirTemp("", "console-rule-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	// Deterministic file names, and the edited rule last, so that a duplicate identifier between
	// the edit and its own context is reported rather than silently shadowed.
	for name, body := range context {
		if err := os.WriteFile(filepath.Join(dir, "ctx-"+name+".yar"), []byte(body), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "zz-edited.yar"), []byte(text), 0o644); err != nil {
		return err
	}
	_, err = c.CompileDir(dir)
	return err
}

// CompileDir compiles every .yar file under dir into one blob, returning the blob's bytes.
//
// On failure it returns a nil blob and an error carrying yr's own diagnostic text. The message is
// passed through deliberately: an analyst fixing a rule needs the compiler's words and line
// number, not a paraphrase.
func (c *Compiler) CompileDir(dir string) ([]byte, error) {
	out, err := os.CreateTemp("", "console-*.yarc")
	if err != nil {
		return nil, err
	}
	outPath := out.Name()
	out.Close()
	defer os.Remove(outPath)

	cmd := exec.Command(c.yr, "compile", "-o", outPath, dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader("")
	runErr := cmd.Run()

	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, fmt.Errorf("rule compilation failed:\n%s", msg)
	}
	blob, err := os.ReadFile(outPath)
	if err != nil {
		// yr exited 0 but wrote nothing: treat as failure rather than shipping an empty rule set.
		return nil, errors.New("rule compilation produced no output")
	}
	if len(blob) == 0 {
		return nil, errors.New("rule compilation produced an empty blob")
	}
	return blob, nil
}
