package phptaint

import (
	"bytes"
	"testing"
)

// hasLayer reports whether any resolved layer contains want.
func hasLayer(ls []Layer, want string) bool {
	for _, l := range ls {
		if bytes.Contains(l.Data, []byte(want)) {
			return true
		}
	}
	return false
}

func TestResolvedVarSink(t *testing.T) {
	// $ohx is built from chr()+concat to "assert", then $ohx($_POST[..]).
	// The resolver must emit a layer with the literal assert( call adjacent to $_POST.
	src := []byte(`<?php $ohx=chr(97)."s".chr(115)."ert"; @$ohx(@$_POST["data"]); die(); ?>`)
	ls := ResolvedLayers(src)
	if !hasLayer(ls, "assert(") {
		t.Fatalf("expected a resolved layer containing assert(, got %+v", ls)
	}
	if !hasLayer(ls, "$_POST") {
		t.Fatalf("expected the resolved layer to retain the request superglobal")
	}
}

func TestResolvedVarSinkNoFP(t *testing.T) {
	// A variable assigned a NON-sink string and then called — no resolved sink layer.
	src := []byte(`<?php $g="greet"; $g($_GET["name"]); ?>`)
	ls := ResolvedLayers(src)
	if hasLayer(ls, "eval(") || hasLayer(ls, "system(") || hasLayer(ls, "assert(") {
		t.Fatalf("non-sink variable must not produce a resolved-sink layer: %+v", ls)
	}
}

func TestResolvedVarSinkBounded(t *testing.T) {
	// Pathological input must not panic or run unbounded.
	src := bytes.Repeat([]byte(`$x=chr(97).chr(115); $x(`), 60000)
	ls := ResolvedLayers(src) //nolint:ifshort
	_ = ls // no panic, returns within bounds
}

func TestResolvedVarReassignmentNoFP(t *testing.T) {
	// $f is assigned a sink name, then REASSIGNED to a non-sink, then called with request.
	// Last-write-wins + clear-on-non-sink must NOT resolve $f to exec( -> no false positive.
	src := []byte(`<?php $f='exec'; $f='executeQuery'; $f($_GET['q']); ?>`)
	if hasLayer(ResolvedLayers(src), "exec(") {
		t.Fatalf("reassigned-away sink must not resolve to exec( (last-write-wins)")
	}
	// Control: a single sink assignment to the same var still resolves.
	src2 := []byte(`<?php $f='exec'; $f($_GET['q']); ?>`)
	if !hasLayer(ResolvedLayers(src2), "exec(") {
		t.Fatalf("single sink assignment should still resolve to exec(")
	}
}
