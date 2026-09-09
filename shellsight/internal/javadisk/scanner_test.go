package javadisk

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAnalyzeArtifactRoutesSourceAndPhysicalArtifactPath(t *testing.T) {
	path := `C:\physical\webapps\ROOT\shell.jsp`
	data := []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)
	result := AnalyzeArtifact(path, data, DefaultOptions())
	if len(result.Diagnostics) != 0 || len(result.Findings) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if result.Findings[0].ArtifactPath != path {
		t.Fatalf("ArtifactPath=%q want %q", result.Findings[0].ArtifactPath, path)
	}
}

func TestAnalyzeArtifactDispatchesJSPAliases(t *testing.T) {
	data := []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)
	for _, path := range []string{"shell.jsw", "shell.jsv", "shell.jhtml"} {
		t.Run(path, func(t *testing.T) {
			result := AnalyzeArtifact(path, data, DefaultOptions())
			if len(result.Findings) != 1 || result.Findings[0].ArtifactPath != path {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestAnalyzeArtifactDispatchesJavaAndClassAndIgnoresOtherFiles(t *testing.T) {
	java := AnalyzeArtifact("Shell.java", []byte(`class Shell { void x(HttpServletRequest request) { Runtime.getRuntime().exec(request.getParameter("x")); } }`), DefaultOptions())
	if len(java.Findings) != 1 || java.Findings[0].ArtifactPath != "Shell.java" {
		t.Fatalf("java=%+v", java)
	}
	classData, _ := classBytes(t, classSpec{})
	class := AnalyzeArtifact("Shell.class", classData, DefaultOptions())
	if len(class.Findings) != 0 || len(class.Diagnostics) != 0 {
		t.Fatalf("class=%+v", class)
	}
	if got := AnalyzeArtifact("notes.txt", []byte("anything"), DefaultOptions()); len(got.Findings) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("other=%+v", got)
	}
}

func TestAnalyzeArtifactIsolatesParserPanic(t *testing.T) {
	parser := func([]byte, Limits) (*classModel, error) { panic("fixture") }
	result := analyzeArtifactContextWithParser(
		context.Background(), "Bad.class", []byte("x"), DefaultOptions(), parser,
	)
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != diagParserPanic {
		t.Fatalf("result=%+v", result)
	}
}

func TestAnalyzeArtifactSanitizesAndBoundsParserPanicText(t *testing.T) {
	parser := func([]byte, Limits) (*classModel, error) {
		panic("bad\r\n\t" + strings.Repeat("x", 300))
	}
	path := "Bad\r\n" + strings.Repeat("y", 300) + ".class"
	result := analyzeArtifactContextWithParser(
		context.Background(), path, []byte("x"), DefaultOptions(), parser,
	)
	assertBoundedDiagnostic(t, result, diagParserPanic)
}

func TestAnalyzeArtifactSanitizesAndBoundsParserErrors(t *testing.T) {
	parser := func([]byte, Limits) (*classModel, error) {
		return nil, errors.New("bad\r\n\t" + strings.Repeat("x", 300))
	}
	result := analyzeArtifactContextWithParser(
		context.Background(), "Bad.class", []byte("x"), DefaultOptions(), parser,
	)
	assertBoundedDiagnostic(t, result, diagClassMalformed)
}

func TestAnalyzeArtifactReportsUnsupportedClassVersion(t *testing.T) {
	data, _ := classBytes(t, classSpec{Major: 71})
	result := AnalyzeArtifact("Future.class", data, DefaultOptions())
	assertBoundedDiagnostic(t, result, diagClassUnsupported)
}

func TestAnalyzeArtifactEnforcesArtifactBudgetBeforeParsing(t *testing.T) {
	called := false
	parser := func([]byte, Limits) (*classModel, error) {
		called = true
		return nil, nil
	}
	opts := DefaultOptions()
	opts.Limits.MaxArtifactBytes = 1
	result := analyzeArtifactContextWithParser(
		context.Background(), "Large.class", []byte("xx"), opts, parser,
	)
	assertBoundedDiagnostic(t, result, diagAnalysisBudget)
	if called {
		t.Fatal("parser called for artifact over byte budget")
	}
}

func TestAnalyzeArtifactContextReturnsPreCancelledDiagnostic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := AnalyzeArtifactContext(ctx, "Cancelled.class", []byte("x"), DefaultOptions())
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != diagCancelled {
		t.Fatalf("result=%+v", result)
	}
}

func TestAnalyzeArtifactContextChecksCancellationAfterParsing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	parser := func([]byte, Limits) (*classModel, error) {
		cancel()
		return &classModel{}, nil
	}
	result := analyzeArtifactContextWithParser(
		ctx, "Cancelled.class", []byte("x"), DefaultOptions(), parser,
	)
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != diagCancelled {
		t.Fatalf("result=%+v", result)
	}
}

func TestAnalyzeArtifactParserInjectionIsConcurrentAndIsolated(t *testing.T) {
	tests := []struct {
		name   string
		parser func([]byte, Limits) (*classModel, error)
		code   string
	}{
		{"success", func([]byte, Limits) (*classModel, error) { return &classModel{}, nil }, ""},
		{"error", func([]byte, Limits) (*classModel, error) { return nil, errors.New("fixture") }, diagClassMalformed},
		{"panic", func([]byte, Limits) (*classModel, error) { panic("fixture") }, diagParserPanic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for range 64 {
				result := analyzeArtifactContextWithParser(
					context.Background(), test.name+".class", []byte("x"), DefaultOptions(), test.parser,
				)
				if test.code == "" {
					if len(result.Findings) != 0 || len(result.Diagnostics) != 0 {
						t.Fatalf("result=%+v", result)
					}
					continue
				}
				if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != test.code {
					t.Fatalf("result=%+v", result)
				}
			}
		})
	}
}

func assertBoundedDiagnostic(t *testing.T, result Result, code string) {
	t.Helper()
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 {
		t.Fatalf("result=%+v", result)
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Code != code || len(diagnostic.Artifact) > maxDiagnosticTextBytes ||
		len(diagnostic.Detail) > maxDiagnosticTextBytes ||
		strings.ContainsAny(diagnostic.Artifact, "\r\n\t") || strings.ContainsAny(diagnostic.Detail, "\r\n\t") {
		t.Fatalf("diagnostic=%+v", diagnostic)
	}
}
