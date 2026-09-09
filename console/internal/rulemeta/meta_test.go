package rulemeta

import "testing"

const yaraForgeShape = `
rule MALPEDIA_Win_Virut_Auto {
   meta:
      description = "Detects Virut, a polymorphic file infector"
      author = "Malpedia"
      id = "8b4b1e2c-1111-4b0e-9a11-000000000000"
      date = "2023-04-11"
      modified = "2024-02-02"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/"
      score = 75
      quality = 85
      tags = "FILE"
   strings:
      $a = { 8b 45 08 }
   condition:
      $a
}
`

func TestParseReadsDescriptionAndScore(t *testing.T) {
	got := Parse(yaraForgeShape)
	if got.Description != "Detects Virut, a polymorphic file infector" {
		t.Errorf("Description = %q", got.Description)
	}
	if got.Score == nil || *got.Score != 75 {
		t.Errorf("Score = %v, want 75", got.Score)
	}
}

func TestParseCollectsEveryKeyItSaw(t *testing.T) {
	got := Parse(yaraForgeShape)
	for k, want := range map[string]string{
		"author":   "Malpedia",
		"date":     "2023-04-11",
		"quality":  "85",
		"tags":     "FILE",
		"modified": "2024-02-02",
	} {
		if got.Keys[k] != want {
			t.Errorf("Keys[%q] = %q, want %q", k, got.Keys[k], want)
		}
	}
}

func TestParseStopsAtTheStringsSection(t *testing.T) {
	// A key-looking line after strings: is not metadata. Without a stop condition the parser would
	// swallow every YARA string definition as a meta key.
	got := Parse(yaraForgeShape)
	if _, ok := got.Keys["$a"]; ok {
		t.Error("picked up a string definition as a meta key")
	}
	// Nine, not eight: the fixture declares description, author, id, date, modified, reference,
	// score, quality and tags before strings:. reference is the only line here whose value carries
	// "//" inside quotes, so it is load-bearing for unquote as well.
	if len(got.Keys) != 9 {
		t.Errorf("collected %d keys, want the 9 declared before strings:: %v", len(got.Keys), got.Keys)
	}
}

func TestParseIsNotTerminatedByASectionNameInsideADescription(t *testing.T) {
	// The exact shape that defeats a block-delimited parser. See spec §2.4.
	got := Parse(`
rule R {
   meta:
      description = "matches on strings: and condition: inside webshells"
      score = 60
   condition:
      true
}
`)
	if got.Description != "matches on strings: and condition: inside webshells" {
		t.Errorf("Description = %q", got.Description)
	}
	if got.Score == nil || *got.Score != 60 {
		t.Errorf("Score = %v, want 60 — parsing stopped early", got.Score)
	}
}

func TestParseKeepsAnEqualsSignInsideAValue(t *testing.T) {
	got := Parse(`
rule R {
   meta:
      description = "detects eval($_POST[x]) = classic backdoor"
   condition:
      true
}
`)
	if got.Description != "detects eval($_POST[x]) = classic backdoor" {
		t.Errorf("Description = %q — split on the wrong equals sign", got.Description)
	}
}

func TestParseReturnsNothingWithoutAMetaBlock(t *testing.T) {
	// 17 rules in the library have no meta block. That is not an error.
	got := Parse(`
rule R {
   strings:
      $a = "x"
   condition:
      $a
}
`)
	if got.Description != "" || got.Score != nil || len(got.Keys) != 0 {
		t.Errorf("got %+v, want an empty Meta", got)
	}
	if got.HasBlock {
		t.Error("HasBlock is true for a rule with no meta: block")
	}
}

func TestParseDropsANonIntegerScore(t *testing.T) {
	// signature-base occasionally carries prose where a number is expected. A rule is still worth
	// storing; the score is simply absent.
	got := Parse(`
rule R {
   meta:
      score = "high"
   condition:
      true
}
`)
	if got.Score != nil {
		t.Errorf("Score = %v, want nil for a non-integer", got.Score)
	}
	if got.Keys["score"] != "high" {
		t.Errorf("Keys[score] = %q — the raw value should survive even when it is not numeric",
			got.Keys["score"])
	}
}

func TestParseAcceptsAQuotedScore(t *testing.T) {
	got := Parse("rule R {\n meta:\n  score = \"70\"\n condition:\n  true\n}")
	if got.Score == nil || *got.Score != 70 {
		t.Errorf("Score = %v, want 70", got.Score)
	}
}

func TestParseHandlesAnInlineMetaBlock(t *testing.T) {
	// signature-base uses a comment on the meta: line in places.
	got := Parse(`
rule R {
   meta:   // provenance
      description = "x"
   condition:
      true
}
`)
	if got.Description != "x" {
		t.Errorf("Description = %q — a trailing comment on the meta: line broke detection", got.Description)
	}
}

func TestParseIgnoresACommentedOutKey(t *testing.T) {
	got := Parse(`
rule R {
   meta:
      // description = "old"
      description = "new"
   condition:
      true
}
`)
	if got.Description != "new" {
		t.Errorf("Description = %q, want the uncommented value", got.Description)
	}
}
