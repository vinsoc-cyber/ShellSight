package javadisk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"shellsight/internal/safearchive"
)

type archiveBudget struct {
	entries  int
	expanded int64
	classes  int
	retained int64
	digests  map[[sha256.Size]byte]struct{}
}

type archiveScanner struct {
	ctx     context.Context
	outer   string
	opts    Options
	parser  classParser
	budget  *archiveBudget
	classes map[string]*classModel
	results *boundedResults
}

type boundedResults struct {
	maxFindings int
	findings    []Finding
	diagnostics map[string]*diagnosticAggregate
	seen        map[string]struct{}
	limitHit    bool
}

type diagnosticAggregate struct {
	diagnostic Diagnostic
	examples   []string
}

func AnalyzePath(ctx context.Context, artifactPath string, opts Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	if ctx.Err() != nil {
		return diagnosticResult(artifactPath, diagCancelled, "analysis cancelled")
	}
	extension := strings.ToLower(filepath.Ext(artifactPath))
	if isArchiveExtension(extension) {
		archiveFile, err := os.Open(artifactPath)
		if err != nil {
			return diagnosticResult(artifactPath, diagArtifactRead, fmt.Sprintf("open Java archive: %v", err))
		}
		defer archiveFile.Close()
		info, err := archiveFile.Stat()
		if err != nil {
			return diagnosticResult(artifactPath, diagArtifactRead, fmt.Sprintf("open Java archive: %v", err))
		}
		reader, err := zip.NewReader(archiveFile, info.Size())
		if (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || reader == nil {
			return diagnosticResult(artifactPath, diagArtifactRead, fmt.Sprintf("open Java archive: %v", err))
		}
		if err := safearchive.ValidateZIPLocalHeaders(archiveFile, info.Size(), reader.File); err != nil {
			return diagnosticResult(artifactPath, diagArtifactRead, fmt.Sprintf("validate Java archive: %v", err))
		}
		return analyzeArchiveFiles(ctx, artifactPath, reader.File, opts, parseClass)
	}
	if extension != ".class" && !isJavaSourceExtension(extension) && !isJSPSourceExtension(extension) {
		return Result{}
	}
	data, diagnostic := readLooseArtifact(ctx, artifactPath, opts.Limits.MaxArtifactBytes)
	if diagnostic != nil {
		return Result{Diagnostics: []Diagnostic{*diagnostic}}
	}
	return AnalyzeArtifactContext(ctx, artifactPath, data, opts)
}

func AnalyzePaths(ctx context.Context, paths []string, opts Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	results := newBoundedResults(opts.Limits.MaxFindings)
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	groups := make(map[string]map[string]*classModel)
	groupKeys := make([]string, 0)
	classes, retained := 0, int64(0)

	cancelled := false
pathLoop:
	for _, artifactPath := range ordered {
		if ctx.Err() != nil {
			results.addDiagnostic(newDiagnostic(artifactPath, diagCancelled, "analysis cancelled"))
			cancelled = true
			break
		}
		extension := strings.ToLower(filepath.Ext(artifactPath))
		switch {
		case isArchiveExtension(extension), isJavaSourceExtension(extension), isJSPSourceExtension(extension):
			result := AnalyzePath(ctx, artifactPath, opts)
			results.addResult(result, "")
			if hasDiagnosticCode(result.Diagnostics, diagCancelled) {
				cancelled = true
				break pathLoop
			}
			if ctx.Err() != nil {
				results.addDiagnostic(newDiagnostic(artifactPath, diagCancelled, "analysis cancelled"))
				cancelled = true
				break pathLoop
			}
		case extension == ".class":
			if classes >= opts.Limits.MaxClasses {
				results.addDiagnostic(newDiagnostic(artifactPath, diagAnalysisBudget, "class limit reached"))
				continue
			}
			data, diagnostic := readLooseArtifact(ctx, artifactPath, opts.Limits.MaxArtifactBytes)
			if diagnostic != nil {
				results.addDiagnostic(*diagnostic)
				if diagnostic.Code == diagCancelled {
					cancelled = true
					break pathLoop
				}
				continue
			}
			if ctx.Err() != nil {
				results.addDiagnostic(newDiagnostic(artifactPath, diagCancelled, "analysis cancelled"))
				cancelled = true
				break pathLoop
			}
			classes++
			if retained+int64(len(data)) > opts.Limits.MaxRetainedClassBytes {
				results.addDiagnostic(newDiagnostic(artifactPath, diagAnalysisBudget, "retained class byte limit reached"))
				continue
			}
			retained += int64(len(data))
			class, diagnostic := parseClassIsolated(artifactPath, data, opts.Limits)
			if diagnostic != nil {
				results.addDiagnostic(*diagnostic)
				continue
			}
			key := looseApplicationGroup(artifactPath)
			if groups[key] == nil {
				groups[key] = make(map[string]*classModel)
				groupKeys = append(groupKeys, key)
			}
			groups[key][artifactPath] = class
		}
	}

	sort.Strings(groupKeys)
	if cancelled {
		return results.finish()
	}
	for _, key := range groupKeys {
		if ctx.Err() != nil {
			results.addDiagnostic(newDiagnostic(key, diagCancelled, "analysis cancelled"))
			break
		}
		result := analyzeClassesContext(ctx, key, groups[key], opts)
		results.addResult(result, "")
		if hasDiagnosticCode(result.Diagnostics, diagCancelled) {
			break
		}
	}
	return results.finish()
}

func analyzeArchiveBytes(
	ctx context.Context,
	outer string,
	data []byte,
	opts Options,
	parser classParser,
) Result {
	source := bytes.NewReader(data)
	size := int64(len(data))
	reader, err := zip.NewReader(source, size)
	if (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || reader == nil {
		return diagnosticResult(outer, diagArtifactRead, fmt.Sprintf("open Java archive: %v", err))
	}
	if err := safearchive.ValidateZIPLocalHeaders(source, size, reader.File); err != nil {
		return diagnosticResult(outer, diagArtifactRead, fmt.Sprintf("validate Java archive: %v", err))
	}
	return analyzeArchiveFiles(ctx, outer, reader.File, opts, parser)
}

func analyzeArchiveFiles(
	ctx context.Context,
	outer string,
	files []*zip.File,
	opts Options,
	parser classParser,
) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	results := newBoundedResults(opts.Limits.MaxFindings)
	scanner := &archiveScanner{
		ctx: ctx, outer: outer, opts: opts, parser: parser,
		budget:  &archiveBudget{digests: make(map[[sha256.Size]byte]struct{})},
		classes: make(map[string]*classModel),
		results: results,
	}
	scanner.scan(files, outer, 0)
	if ctx.Err() != nil {
		results.addDiagnostic(newDiagnostic(outer, diagCancelled, "analysis cancelled"))
	} else if len(scanner.classes) != 0 {
		results.addResult(analyzeClassesContext(ctx, outer, scanner.classes, opts), outer)
	}
	return results.finish()
}

func (scanner *archiveScanner) scan(files []*zip.File, logicalRoot string, depth int) {
	if scanner.ctx.Err() != nil {
		return
	}
	if len(files) > scanner.opts.Limits.MaxArchiveEntries-scanner.budget.entries {
		scanner.results.addDiagnostic(newDiagnostic(logicalRoot, diagArchiveBudget, "archive entry limit reached"))
		return
	}
	scanner.budget.entries += len(files)

	members := make([]safearchive.ZIPEntry, 0, len(files))
	for _, entry := range safearchive.PrepareZIP(files, archivePriority) {
		if entry.Err != nil {
			artifact := logicalRoot
			if entry.Name != "" {
				artifact = logicalMemberPath(logicalRoot, entry.Name)
			}
			scanner.results.addDiagnostic(newDiagnostic(artifact, diagArtifactRead, entry.Err.Error()))
			continue
		}
		members = append(members, entry)
	}

	for _, member := range members {
		if scanner.ctx.Err() != nil {
			return
		}
		if member.Priority == 3 {
			continue
		}
		logicalPath := logicalMemberPath(logicalRoot, member.Name)
		data, ok := scanner.readMember(member.File, logicalPath)
		if !ok {
			continue
		}
		digest := sha256.Sum256(data)
		if _, duplicate := scanner.budget.digests[digest]; duplicate {
			continue
		}
		if len(scanner.budget.digests) < scanner.opts.Limits.MaxArchiveEntries {
			scanner.budget.digests[digest] = struct{}{}
		}

		extension := strings.ToLower(path.Ext(member.Name))
		switch {
		case extension == ".class":
			scanner.addClass(logicalPath, data)
		case isJavaSourceExtension(extension) || isJSPSourceExtension(extension):
			if scanner.ctx.Err() != nil {
				return
			}
			findings := Analyze(logicalPath, data)
			for i := range findings {
				findings[i].Evidence = prefixLogicalEvidence(logicalPath, findings[i].Evidence)
				findings[i].ArtifactPath = scanner.outer
			}
			scanner.results.addResult(Result{Findings: findings}, scanner.outer)
		case isArchiveExtension(extension):
			if depth >= scanner.opts.Limits.MaxNestedDepth {
				scanner.results.addDiagnostic(newDiagnostic(logicalPath, diagArchiveBudget, "nested archive depth limit reached"))
				continue
			}
			source := bytes.NewReader(data)
			size := int64(len(data))
			reader, err := zip.NewReader(source, size)
			if (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || reader == nil {
				scanner.results.addDiagnostic(newDiagnostic(logicalPath, diagArtifactRead, fmt.Sprintf("open nested Java archive: %v", err)))
				continue
			}
			if err := safearchive.ValidateZIPLocalHeaders(source, size, reader.File); err != nil {
				scanner.results.addDiagnostic(newDiagnostic(logicalPath, diagArtifactRead, fmt.Sprintf("validate nested Java archive: %v", err)))
				continue
			}
			scanner.scan(reader.File, logicalPath, depth+1)
		}
	}
}

func (scanner *archiveScanner) readMember(file *zip.File, logicalPath string) ([]byte, bool) {
	limits := scanner.opts.Limits
	data, err := safearchive.ReadZIPEntry(scanner.ctx, file, safearchive.ZIPLimits{
		MaxCompressedBytes: limits.MaxCompressedEntryBytes,
		MaxExpandedBytes:   limits.MaxEntryBytes,
		MaxTotalBytes:      limits.MaxArchiveBytes,
		MaxRatio:           limits.MaxCompressionRatio,
		RatioFloor:         limits.CompressionRatioFloor,
	}, &scanner.budget.expanded)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false
		}
		code := diagArtifactRead
		if safearchive.IsBudgetError(err) {
			code = diagArchiveBudget
		}
		scanner.results.addDiagnostic(newDiagnostic(logicalPath, code, err.Error()))
		return nil, false
	}
	return data, true
}

func (scanner *archiveScanner) addClass(logicalPath string, data []byte) {
	if scanner.ctx.Err() != nil {
		return
	}
	if scanner.budget.classes >= scanner.opts.Limits.MaxClasses {
		scanner.results.addDiagnostic(newDiagnostic(logicalPath, diagAnalysisBudget, "class limit reached"))
		return
	}
	scanner.budget.classes++
	if scanner.budget.retained+int64(len(data)) > scanner.opts.Limits.MaxRetainedClassBytes {
		scanner.results.addDiagnostic(newDiagnostic(logicalPath, diagAnalysisBudget, "retained class byte limit reached"))
		return
	}
	scanner.budget.retained += int64(len(data))
	if scanner.ctx.Err() != nil {
		return
	}
	class, diagnostic := parseClassIsolatedWith(logicalPath, data, scanner.opts.Limits, scanner.parser)
	if diagnostic != nil {
		scanner.results.addDiagnostic(*diagnostic)
		return
	}
	scanner.classes[logicalPath] = class
}

func readLooseArtifact(ctx context.Context, artifactPath string, limit int64) ([]byte, *Diagnostic) {
	file, err := os.Open(artifactPath)
	if err != nil {
		diagnostic := newDiagnostic(artifactPath, diagArtifactRead, fmt.Sprintf("open artifact: %v", err))
		return nil, &diagnostic
	}
	defer file.Close()
	limited := &io.LimitedReader{R: file, N: limit}
	var output bytes.Buffer
	buffer := make([]byte, 32<<10)
	for {
		if ctx.Err() != nil {
			diagnostic := newDiagnostic(artifactPath, diagCancelled, "analysis cancelled")
			return nil, &diagnostic
		}
		n, readErr := limited.Read(buffer)
		if n != 0 {
			_, _ = output.Write(buffer[:n])
			if ctx.Err() != nil {
				diagnostic := newDiagnostic(artifactPath, diagCancelled, "analysis cancelled")
				return nil, &diagnostic
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				diagnostic := newDiagnostic(artifactPath, diagArtifactRead, fmt.Sprintf("read artifact: %v", readErr))
				return nil, &diagnostic
			}
			break
		}
	}
	var probe [1]byte
	n, err := file.Read(probe[:])
	if err != nil && err != io.EOF {
		diagnostic := newDiagnostic(artifactPath, diagArtifactRead, fmt.Sprintf("probe artifact size: %v", err))
		return nil, &diagnostic
	}
	if n != 0 {
		diagnostic := newDiagnostic(artifactPath, diagAnalysisBudget, "artifact exceeds byte limit")
		return nil, &diagnostic
	}
	return output.Bytes(), nil
}

func archivePriority(name string) int {
	extension := strings.ToLower(path.Ext(name))
	if extension == ".class" || isJavaSourceExtension(extension) || isJSPSourceExtension(extension) {
		return 0
	}
	if isArchiveExtension(extension) {
		if strings.HasPrefix(strings.ToLower(name), "web-inf/lib/") {
			return 1
		}
		return 2
	}
	return 3
}

func isArchiveExtension(extension string) bool {
	return extension == ".jar" || extension == ".war"
}

func logicalMemberPath(root, name string) string {
	return root + "!/" + name
}

func prefixLogicalEvidence(logicalPath, evidence string) string {
	return boundedEvidenceComponent("artifact="+logicalPath+" "+evidence, 1024)
}

func looseApplicationGroup(artifactPath string) string {
	cleaned := filepath.Clean(artifactPath)
	slashed := filepath.ToSlash(cleaned)
	parts := strings.Split(slashed, "/")
	boundary := -1
	for index := 0; index+1 < len(parts); index++ {
		if strings.EqualFold(parts[index], "WEB-INF") && strings.EqualFold(parts[index+1], "classes") {
			boundary = index + 1
		}
	}
	if boundary < 0 {
		return cleaned
	}
	return filepath.FromSlash(strings.Join(parts[:boundary+1], "/"))
}

func newBoundedResults(maxFindings int) *boundedResults {
	return &boundedResults{
		maxFindings: maxFindings,
		diagnostics: make(map[string]*diagnosticAggregate),
		seen:        make(map[string]struct{}),
	}
}

func (results *boundedResults) addResult(result Result, physicalPath string) {
	for _, finding := range result.Findings {
		if physicalPath != "" {
			finding.ArtifactPath = physicalPath
		}
		results.addFinding(finding)
	}
	for _, diagnostic := range result.Diagnostics {
		results.addDiagnostic(diagnostic)
	}
}

func (results *boundedResults) addFinding(finding Finding) {
	key := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", finding.Score, finding.Family, finding.Rule, finding.Evidence, finding.ArtifactPath)
	if _, duplicate := results.seen[key]; duplicate {
		return
	}
	if len(results.findings) >= results.maxFindings {
		results.limitHit = true
		return
	}
	results.seen[key] = struct{}{}
	results.findings = append(results.findings, finding)
}

func (results *boundedResults) addDiagnostic(diagnostic Diagnostic) {
	count := diagnostic.Count
	if count <= 0 {
		count = 1
	}
	diagnostic.Artifact = boundedDiagnosticText(diagnostic.Artifact)
	diagnostic.Detail = boundedDiagnosticText(diagnostic.Detail)
	item := results.diagnostics[diagnostic.Code]
	if item == nil {
		diagnostic.Count = 0
		item = &diagnosticAggregate{diagnostic: diagnostic}
		results.diagnostics[diagnostic.Code] = item
	} else if diagnostic.Artifact < item.diagnostic.Artifact {
		item.diagnostic.Artifact = diagnostic.Artifact
	}
	item.diagnostic.Count += count
	item.examples = retainDiagnosticExample(item.examples, diagnostic.Detail)
}

func (results *boundedResults) finish() Result {
	if results.limitHit {
		results.addDiagnostic(newDiagnostic("", diagAnalysisBudget, "finding limit reached"))
	}
	sort.Slice(results.findings, func(i, j int) bool {
		if results.findings[i].ArtifactPath != results.findings[j].ArtifactPath {
			return results.findings[i].ArtifactPath < results.findings[j].ArtifactPath
		}
		if results.findings[i].Rule != results.findings[j].Rule {
			return results.findings[i].Rule < results.findings[j].Rule
		}
		return results.findings[i].Evidence < results.findings[j].Evidence
	})
	return Result{Findings: results.findings, Diagnostics: results.finishedDiagnostics()}
}

func retainDiagnosticExample(examples []string, detail string) []string {
	index := sort.SearchStrings(examples, detail)
	if index < len(examples) && examples[index] == detail {
		return examples
	}
	examples = append(examples, "")
	copy(examples[index+1:], examples[index:])
	examples[index] = detail
	if len(examples) > 3 {
		examples = examples[:3]
	}
	return examples
}

func (results *boundedResults) finishedDiagnostics() []Diagnostic {
	codes := make([]string, 0, len(results.diagnostics))
	for code := range results.diagnostics {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	diagnostics := make([]Diagnostic, 0, len(codes))
	for _, code := range codes {
		item := results.diagnostics[code]
		diagnostic := item.diagnostic
		diagnostic.Detail = boundedDiagnosticText(strings.Join(item.examples, " | "))
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics
}
