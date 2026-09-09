package javadisk

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"shellsight/internal/safearchive"
)

type archiveEntryFixture struct {
	name   string
	data   []byte
	method uint16
}

func zipFixture(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]archiveEntryFixture, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, archiveEntryFixture{name: name, data: entries[name], method: zip.Deflate})
	}
	return zipFixtureOrdered(t, ordered)
}

func zipFixtureOrdered(t *testing.T, entries []archiveEntryFixture) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: entry.method}
		part, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create ZIP entry %q: %v", entry.name, err)
		}
		if _, err := part.Write(entry.data); err != nil {
			t.Fatalf("write ZIP entry %q: %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP writer: %v", err)
	}
	return buffer.Bytes()
}

func zip64Fixture(t *testing.T, name string, data []byte, reportedSize uint64) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: name, Method: zip.Store, CRC32: crc32.ChecksumIEEE(data)}
	header.CompressedSize64 = uint64(len(data))
	header.UncompressedSize64 = reportedSize
	part, err := writer.CreateRaw(header)
	if err != nil {
		t.Fatalf("create ZIP64 entry: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write ZIP64 entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP64 writer: %v", err)
	}
	return addZIP64LocalSizes(t, buffer.Bytes(), reportedSize, uint64(len(data)))
}

func addZIP64LocalSizes(t *testing.T, data []byte, uncompressed, compressed uint64) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	local := bytes.Index(result, []byte("PK\x03\x04"))
	eocd := bytes.LastIndex(result, []byte("PK\x05\x06"))
	if local < 0 || eocd < 0 || local+30 > len(result) {
		t.Fatal("ZIP local header or EOCD not found")
	}
	nameLength := int(binary.LittleEndian.Uint16(result[local+26 : local+28]))
	extraLength := int(binary.LittleEndian.Uint16(result[local+28 : local+30]))
	insert := local + 30 + nameLength + extraLength
	var payload []byte
	if binary.LittleEndian.Uint32(result[local+22:local+26]) == ^uint32(0) {
		payload = binary.LittleEndian.AppendUint64(payload, uncompressed)
	}
	if binary.LittleEndian.Uint32(result[local+18:local+22]) == ^uint32(0) {
		payload = binary.LittleEndian.AppendUint64(payload, compressed)
	}
	if len(payload) == 0 {
		t.Fatal("ZIP local header has no ZIP64 size sentinel")
	}
	extra := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(extra[0:2], 0x0001)
	binary.LittleEndian.PutUint16(extra[2:4], uint16(len(payload)))
	copy(extra[4:], payload)
	if insert > len(result) || extraLength > int(^uint16(0))-len(extra) {
		t.Fatal("invalid ZIP local extra fixture")
	}
	result = append(result, make([]byte, len(extra))...)
	copy(result[insert+len(extra):], result[insert:len(result)-len(extra)])
	copy(result[insert:], extra)
	binary.LittleEndian.PutUint16(result[local+28:local+30], uint16(extraLength+len(extra)))
	eocd += len(extra)
	centralOffset := binary.LittleEndian.Uint32(result[eocd+16 : eocd+20])
	binary.LittleEndian.PutUint32(result[eocd+16:eocd+20], centralOffset+uint32(len(extra)))
	return result
}

func writeFixtureClass(t *testing.T, root, relative, fixtureName string) string {
	t.Helper()
	if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(filepath.ToSlash(relative), "../") {
		t.Fatalf("unsafe fixture relative path %q", relative)
	}
	full := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("fixture path escapes root: %q", relative)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("create fixture parent: %v", err)
	}
	if err := os.WriteFile(full, fixtureClass(t, fixtureName), 0o600); err != nil {
		t.Fatalf("write fixture class: %v", err)
	}
	return full
}

func writeArtifactFixture(t *testing.T, root, relativeRoot, fixtureName string) []string {
	t.Helper()
	build, ok := artifactFixtures[fixtureName]
	if !ok {
		t.Fatalf("unknown artifact fixture %q", fixtureName)
	}
	var paths []string
	for _, entry := range build(t) {
		data := entry.Bytes
		var classData []byte
		if data != nil {
			classData = data(t)
		} else {
			classData, _ = classBytes(t, entry.Spec)
		}
		relative := filepath.ToSlash(filepath.Join(relativeRoot, filepath.FromSlash(entry.LogicalPath)))
		full := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("create fixture parent: %v", err)
		}
		if err := os.WriteFile(full, classData, 0o600); err != nil {
			t.Fatalf("write fixture class: %v", err)
		}
		paths = append(paths, full)
	}
	sort.Strings(paths)
	return paths
}

func classPathsUnder(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".class") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk class fixtures: %v", err)
	}
	sort.Strings(paths)
	return paths
}

func TestAnalyzeJarScansClassAndKeepsOuterArtifactPath(t *testing.T) {
	jar := zipFixture(t, map[string][]byte{"x/Shell.class": fixtureClass(t, "request_exec")})
	res := AnalyzeArtifact("app.jar", jar, DefaultOptions())
	finding := findingByRule(res.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.ArtifactPath != "app.jar" || !strings.Contains(finding.Evidence, "app.jar!/x/Shell.class") {
		t.Fatalf("result=%+v", res)
	}
	structural := findingByRule(res.Findings, "javadisk:class-request-exec-structure")
	if structural == nil || structural.ArtifactPath != "app.jar" || !strings.Contains(structural.Evidence, "app.jar!/x/Shell.class") {
		t.Fatalf("structural result=%+v", res)
	}
}

func TestAnalyzeWARScansClassesAndSourceEntries(t *testing.T) {
	war := zipFixture(t, map[string][]byte{
		"WEB-INF/classes/x/Shell.class": fixtureClass(t, "request_exec"),
		"views/shell.jsp":               []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`),
	})
	res := AnalyzeArtifact("app.war", war, DefaultOptions())
	if findingByRule(res.Findings, "javadisk:class-request-exec") == nil {
		t.Fatalf("missing class finding: %+v", res)
	}
	var source *Finding
	for i := range res.Findings {
		if res.Findings[i].Rule == "javadisk:request-exec" {
			source = &res.Findings[i]
		}
	}
	if source == nil || source.ArtifactPath != "app.war" || !strings.Contains(source.Evidence, "app.war!/views/shell.jsp") {
		t.Fatalf("missing source finding: %+v", res)
	}
}

func TestAnalyzeWARScansNestedLibrary(t *testing.T) {
	jar := zipFixture(t, map[string][]byte{"x/Shell.class": fixtureClass(t, "request_exec")})
	war := zipFixture(t, map[string][]byte{"WEB-INF/lib/payload.jar": jar})
	res := AnalyzeArtifact("app.war", war, DefaultOptions())
	finding := findingByRule(res.Findings, "javadisk:class-request-exec")
	if finding == nil || !strings.Contains(finding.Evidence, "app.war!/WEB-INF/lib/payload.jar!/x/Shell.class") {
		t.Fatalf("result=%+v", res)
	}
}

func TestAnalyzeWARSummarizesAcrossNestedLibraryWithinOneApplication(t *testing.T) {
	entries := artifactFixtures["request_exec_helper"](t)
	entryData, _ := classBytes(t, entries[0].Spec)
	helperData, _ := classBytes(t, entries[1].Spec)
	jar := zipFixture(t, map[string][]byte{"fixture/Helper.class": helperData})
	war := zipFixture(t, map[string][]byte{
		"WEB-INF/classes/fixture/Entry.class": entryData,
		"WEB-INF/lib/helper.jar":              jar,
	})
	res := AnalyzeArtifact("app.war", war, DefaultOptions())
	finding := findingByRule(res.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 {
		t.Fatalf("result=%+v", res)
	}
}

func TestArchiveDeduplicatesRelevantContentByDigest(t *testing.T) {
	classData := fixtureClass(t, "request_exec")
	jar := zipFixture(t, map[string][]byte{"a/Shell.class": classData, "b/Shell.class": classData})
	res := AnalyzeArtifact("dupe.jar", jar, DefaultOptions())
	if findingByRule(res.Findings, "javadisk:class-request-exec") == nil || hasDiagnosticCode(res.Diagnostics, diagClassDuplicate) {
		t.Fatalf("result=%+v", res)
	}
}

func TestArchiveRejectsUnsafeLocalPathsBeforeScanningSiblings(t *testing.T) {
	root := t.TempDir()
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	jar := zipFixture(t, map[string][]byte{
		"../outside.jsp":             []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`),
		"C:/drive.jsp":               []byte("ignored"),
		"\\server\\share\\bad.class": fixtureClass(t, "request_exec"),
		"safe/Shell.class":           fixtureClass(t, "request_exec"),
	})
	res := AnalyzeArtifact(filepath.Join(root, "app.jar"), jar, DefaultOptions())
	after, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(before) != len(after) ||
		!diagnosticHasDetail(res.Diagnostics, diagArtifactRead, "unsafe local ZIP entry name") {
		t.Fatalf("before=%v after=%v result=%+v", before, after, res)
	}
}

func TestArchiveReviewRejectsUnsafeLocalPathsAcrossInputs(t *testing.T) {
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	classData := fixtureClass(t, "request_exec")
	unsafeArchive := zipFixture(t, map[string][]byte{
		"../unsafe.jsp":    []byte("ignored"),
		"safe/Shell.class": classData,
	})

	t.Run("AnalyzeArtifact", func(t *testing.T) {
		result := AnalyzeArtifact("hardened.jar", unsafeArchive, DefaultOptions())
		assertUnsafeLocalArchiveRejected(t, result)
	})

	t.Run("nested", func(t *testing.T) {
		outer := zipFixture(t, map[string][]byte{"WEB-INF/lib/payload.jar": unsafeArchive})
		result := AnalyzeArtifact("hardened.war", outer, DefaultOptions())
		assertUnsafeLocalArchiveRejected(t, result)
	})

	t.Run("AnalyzePath", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "hardened.jar")
		if err := os.WriteFile(archivePath, unsafeArchive, 0o600); err != nil {
			t.Fatal(err)
		}
		result := AnalyzePath(context.Background(), archivePath, DefaultOptions())
		assertUnsafeLocalArchiveRejected(t, result)
	})
}

func TestArchiveRejectsLocalMetadataBeforeContentHandling(t *testing.T) {
	mismatched := patchZIPLocalMethod(t, zipFixture(t, map[string][]byte{
		"A.class": []byte("inert-local-mismatch"),
	}), zip.Store)

	assertBytesRejected := func(t *testing.T, name string, data []byte) {
		t.Helper()
		parserCalls := 0
		result := analyzeArtifactContextWithParser(
			context.Background(), name, data, DefaultOptions(),
			func([]byte, Limits) (*classModel, error) {
				parserCalls++
				return nil, errors.New("inert parser reached")
			},
		)
		if parserCalls != 0 || len(result.Findings) != 0 ||
			!diagnosticHasDetail(result.Diagnostics, diagArtifactRead, "local and central method mismatch") {
			t.Fatalf("parserCalls=%d result=%+v", parserCalls, result)
		}
	}

	t.Run("bytes", func(t *testing.T) {
		assertBytesRejected(t, "local-mismatch.jar", mismatched)
	})

	t.Run("nested", func(t *testing.T) {
		outer := zipFixture(t, map[string][]byte{"lib/payload.jar": mismatched})
		assertBytesRejected(t, "nested-local-mismatch.war", outer)
	})

	t.Run("path", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "local-mismatch.jar")
		if err := os.WriteFile(archivePath, mismatched, 0o600); err != nil {
			t.Fatal(err)
		}
		result := AnalyzePath(context.Background(), archivePath, DefaultOptions())
		if len(result.Findings) != 0 ||
			!diagnosticHasDetail(result.Diagnostics, diagArtifactRead, "local and central method mismatch") {
			t.Fatalf("result=%+v", result)
		}
	})
}

func TestArchiveReviewRejectsNormalizedPathCollisionsDeterministically(t *testing.T) {
	malicious := archiveEntryFixture{name: "x/../Shell.class", data: fixtureClass(t, "request_exec"), method: zip.Deflate}
	benignData, _ := classBytes(t, classSpec{Name: "fixture/Benign"})
	benign := archiveEntryFixture{name: "Shell.class", data: benignData, method: zip.Deflate}
	source := archiveEntryFixture{
		name: "safe.jsp", method: zip.Deflate,
		data: []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`),
	}

	first := AnalyzeArtifact("collision.war", zipFixtureOrdered(t, []archiveEntryFixture{malicious, benign, source}), DefaultOptions())
	second := AnalyzeArtifact("collision.war", zipFixtureOrdered(t, []archiveEntryFixture{benign, malicious, source}), DefaultOptions())
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("central-directory order changed result: first=%+v second=%+v", first, second)
	}
	if findingByRule(first.Findings, "javadisk:class-request-exec") != nil ||
		findingByRule(first.Findings, "javadisk:request-exec") == nil ||
		!diagnosticHasDetail(first.Diagnostics, diagArtifactRead, "duplicate normalized archive entry path") {
		t.Fatalf("result=%+v", first)
	}
}

func TestArchiveCorruptionAndCRCFailureDoNotAbortSibling(t *testing.T) {
	archive := zipFixtureOrdered(t, []archiveEntryFixture{
		{name: "bad.jsp", data: []byte("0123456789"), method: zip.Store},
		{name: "good.jsp", data: []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), method: zip.Store},
	})
	archive = corruptStoredEntry(t, archive, "bad.jsp")
	res := AnalyzeArtifact("corrupt.war", archive, DefaultOptions())
	if findingByRule(res.Findings, "javadisk:request-exec") == nil || !hasDiagnosticCode(res.Diagnostics, diagArtifactRead) {
		t.Fatalf("result=%+v", res)
	}
}

func TestArchiveRejectsEncryptedAndUnsupportedMethods(t *testing.T) {
	base := zipFixtureOrdered(t, []archiveEntryFixture{{name: "bad.jsp", data: []byte("x"), method: zip.Store}})
	tests := map[string][]byte{
		"encrypted":   patchZIPFlags(t, base, 1),
		"unsupported": patchZIPMethod(t, base, 99),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			res := AnalyzeArtifact(name+".war", data, DefaultOptions())
			if !hasDiagnosticCode(res.Diagnostics, diagArtifactRead) {
				t.Fatalf("result=%+v", res)
			}
		})
	}
}

func TestArchiveZIP64MetadataCannotBypassEntryLimit(t *testing.T) {
	data := []byte("small")
	archive := zip64Fixture(t, "large.jsp", data, uint64(1)<<32+uint64(len(data)))
	opts := DefaultOptions()
	opts.Limits.MaxEntryBytes = 16
	res := AnalyzeArtifact("zip64.war", archive, opts)
	if !hasDiagnosticCode(res.Diagnostics, diagArchiveBudget) {
		t.Fatalf("result=%+v", res)
	}
}

func TestArchiveEnforcesEverySharedBudget(t *testing.T) {
	classData := fixtureClass(t, "request_exec")
	nested := zipFixture(t, map[string][]byte{"deep/Shell.class": classData})
	doubleNested := zipFixture(t, map[string][]byte{"lib/deep.jar": nested})
	ratioData := bytes.Repeat([]byte("A"), 128<<10)
	tests := []struct {
		name    string
		archive []byte
		set     func(*Limits)
		code    string
	}{
		{"entries", zipFixture(t, map[string][]byte{"a.txt": nil, "b.txt": nil}), func(l *Limits) { l.MaxArchiveEntries = 1 }, diagArchiveBudget},
		{"entry-bytes", zipFixture(t, map[string][]byte{"large.jsp": bytes.Repeat([]byte("x"), 32)}), func(l *Limits) { l.MaxEntryBytes = 16 }, diagArchiveBudget},
		{"compressed-bytes", zipFixtureOrdered(t, []archiveEntryFixture{{name: "large.jsp", data: bytes.Repeat([]byte("x"), 32), method: zip.Store}}), func(l *Limits) { l.MaxCompressedEntryBytes = 16 }, diagArchiveBudget},
		{"archive-bytes", zipFixture(t, map[string][]byte{"a.jsp": bytes.Repeat([]byte("x"), 12), "b.jsp": bytes.Repeat([]byte("y"), 12)}), func(l *Limits) { l.MaxEntryBytes = 16; l.MaxArchiveBytes = 20 }, diagArchiveBudget},
		{"ratio", zipFixture(t, map[string][]byte{"large.jsp": ratioData}), func(l *Limits) { l.CompressionRatioFloor = 1; l.MaxCompressionRatio = 2 }, diagArchiveBudget},
		{"depth", zipFixture(t, map[string][]byte{"outer.jar": doubleNested}), func(l *Limits) { l.MaxNestedDepth = 1 }, diagArchiveBudget},
		{"classes", zipFixture(t, map[string][]byte{"a/Shell.class": classData, "b/Other.class": fixtureClass(t, "branch_join")}), func(l *Limits) { l.MaxClasses = 1 }, diagAnalysisBudget},
		{"retained-class-bytes", zipFixture(t, map[string][]byte{"Shell.class": classData}), func(l *Limits) { l.MaxRetainedClassBytes = int64(len(classData) - 1) }, diagAnalysisBudget},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := DefaultOptions()
			test.set(&opts.Limits)
			res := AnalyzeArtifact("budget.war", test.archive, opts)
			if !hasDiagnosticCode(res.Diagnostics, test.code) {
				t.Fatalf("result=%+v", res)
			}
		})
	}
}

func TestArchiveReviewEnforcesStreamingExpandedLimitsDespiteMetadata(t *testing.T) {
	payload := bytes.Repeat([]byte("streamed-content-"), 32)
	archive := zipFixture(t, map[string][]byte{"large.jsp": payload})
	archive = patchZIPUint32(t, archive, []byte("PK\x01\x02"), 24, 1)
	archive = patchZIPUint32(t, archive, []byte("PK\x07\x08"), 12, 1)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) != 1 || reader.File[0].UncompressedSize64 != 1 {
		t.Fatalf("fixture did not underreport expanded size: reader=%v err=%v", reader, err)
	}

	t.Run("entry", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Limits.MaxEntryBytes = 64
		result := AnalyzeArtifact("streaming.war", archive, opts)
		if !diagnosticHasDetail(result.Diagnostics, diagArchiveBudget, "entry expanded byte limit reached") {
			t.Fatalf("result=%+v", result)
		}
	})

	t.Run("archive", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Limits.MaxEntryBytes = int64(len(payload) + 1)
		opts.Limits.MaxArchiveBytes = 64
		result := AnalyzeArtifact("streaming.war", archive, opts)
		if !diagnosticHasDetail(result.Diagnostics, diagArchiveBudget, "archive expanded byte limit reached") {
			t.Fatalf("result=%+v", result)
		}
	})
}

func TestArchiveReviewCompressedCounterEnforcesActualRawByteLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("actual-compressed-byte-consumption"), 128)
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	const limit = int64(32)
	if int64(compressed.Len()) <= limit {
		t.Fatalf("deflated fixture is only %d bytes", compressed.Len())
	}
	counter := safearchive.NewCompressedCounter(bytes.NewReader(compressed.Bytes()), limit)
	inflater := flate.NewReader(counter)
	defer inflater.Close()
	_, err = io.Copy(io.Discard, inflater)
	if !errors.Is(err, safearchive.ErrCompressedEntryLimit) || counter.BytesRead() != limit+1 {
		t.Fatalf("raw bytes=%d err=%v", counter.BytesRead(), err)
	}
}

func TestArchiveReviewSharesBudgetsAcrossNestedArchives(t *testing.T) {
	requestClass := fixtureClass(t, "request_exec")
	benignClass, _ := classBytes(t, classSpec{Name: "fixture/Benign"})

	t.Run("entries", func(t *testing.T) {
		nested := zipFixture(t, map[string][]byte{"Shell.class": requestClass, "resource.txt": []byte("x")})
		outer := zipFixture(t, map[string][]byte{"WEB-INF/lib/payload.jar": nested})
		opts := DefaultOptions()
		opts.Limits.MaxArchiveEntries = 2
		result := AnalyzeArtifact("entries.war", outer, opts)
		if findingByRule(result.Findings, "javadisk:class-request-exec") != nil || !hasDiagnosticCode(result.Diagnostics, diagArchiveBudget) {
			t.Fatalf("result=%+v", result)
		}
	})

	t.Run("classes", func(t *testing.T) {
		nested := zipFixture(t, map[string][]byte{"Shell.class": requestClass})
		outer := zipFixture(t, map[string][]byte{
			"WEB-INF/classes/Benign.class": benignClass,
			"WEB-INF/lib/payload.jar":      nested,
		})
		opts := DefaultOptions()
		opts.Limits.MaxClasses = 1
		result := AnalyzeArtifact("classes.war", outer, opts)
		if findingByRule(result.Findings, "javadisk:class-request-exec") != nil || !hasDiagnosticCode(result.Diagnostics, diagAnalysisBudget) {
			t.Fatalf("result=%+v", result)
		}
	})

	t.Run("retained-class-bytes", func(t *testing.T) {
		nested := zipFixture(t, map[string][]byte{"Shell.class": requestClass})
		outer := zipFixture(t, map[string][]byte{
			"WEB-INF/classes/Benign.class": benignClass,
			"WEB-INF/lib/payload.jar":      nested,
		})
		opts := DefaultOptions()
		opts.Limits.MaxRetainedClassBytes = int64(max(len(benignClass), len(requestClass)))
		result := AnalyzeArtifact("retained.war", outer, opts)
		if findingByRule(result.Findings, "javadisk:class-request-exec") != nil || !hasDiagnosticCode(result.Diagnostics, diagAnalysisBudget) {
			t.Fatalf("result=%+v", result)
		}
	})
}

func TestArchiveFindingLimitIsGlobalAndDeterministic(t *testing.T) {
	archive := zipFixture(t, map[string][]byte{"Shell.class": fixtureClass(t, "request_exec")})
	opts := DefaultOptions()
	opts.Limits.MaxFindings = 1
	first := AnalyzeArtifact("limit.war", archive, opts)
	second := AnalyzeArtifact("limit.war", archive, opts)
	if len(first.Findings) != 1 || !reflect.DeepEqual(first, second) || !diagnosticHasDetail(first.Diagnostics, diagAnalysisBudget, "finding limit reached") {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestArchiveFindingDedupStateStopsAtFindingLimit(t *testing.T) {
	results := newBoundedResults(2)
	for index := range 10 {
		results.addFinding(Finding{Rule: "rule", Evidence: string(rune('a' + index))})
	}
	if len(results.findings) != 2 || len(results.seen) != 2 || !results.limitHit {
		t.Fatalf("findings=%d seen=%d limitHit=%v", len(results.findings), len(results.seen), results.limitHit)
	}
}

func TestArchiveReviewAggregatesDiagnosticsIncrementally(t *testing.T) {
	results := newBoundedResults(1)
	for index := range 1_000 {
		results.addDiagnostic(newDiagnostic(
			"archive.jar", diagArtifactRead, "example-"+string(rune(index)),
		))
	}
	if len(results.diagnostics) != 1 {
		t.Fatalf("retained %d diagnostic records before finish", len(results.diagnostics))
	}
	result := results.finish()
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Count != 1_000 || strings.Count(result.Diagnostics[0].Detail, " | ") > 2 {
		t.Fatalf("result=%+v", result)
	}
}

func TestArchiveOrderingIsIndependentOfCentralDirectoryOrder(t *testing.T) {
	a := archiveEntryFixture{name: "a/Shell.class", data: fixtureClass(t, "request_exec"), method: zip.Deflate}
	z := archiveEntryFixture{name: "z/shell.jsp", data: []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), method: zip.Deflate}
	first := AnalyzeArtifact("order.war", zipFixtureOrdered(t, []archiveEntryFixture{z, a}), DefaultOptions())
	second := AnalyzeArtifact("order.war", zipFixtureOrdered(t, []archiveEntryFixture{a, z}), DefaultOptions())
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestArchiveCancellationIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := AnalyzeArtifactContext(ctx, "cancelled.jar", zipFixture(t, map[string][]byte{"Shell.class": fixtureClass(t, "request_exec")}), DefaultOptions())
	if len(res.Findings) != 0 || diagnosticCount(res.Diagnostics, diagCancelled) != 1 {
		t.Fatalf("result=%+v", res)
	}
}

func TestArchiveSharedSafetyMigrationPreservesHostileFixtureResults(t *testing.T) {
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	requestClass := fixtureClass(t, "request_exec")
	benignClass, _ := classBytes(t, classSpec{Name: "fixture/Benign"})
	nested := zipFixture(t, map[string][]byte{"deep/Shell.class": requestClass})
	doubleNested := zipFixture(t, map[string][]byte{"lib/deep.jar": nested})
	ratioData := bytes.Repeat([]byte("A"), 128<<10)
	corrupt := zipFixtureOrdered(t, []archiveEntryFixture{
		{name: "bad.jsp", data: []byte("0123456789"), method: zip.Store},
		{name: "good.jsp", data: []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), method: zip.Store},
	})
	corrupt = corruptStoredEntry(t, corrupt, "bad.jsp")
	metadata := zipFixture(t, map[string][]byte{"large.jsp": bytes.Repeat([]byte("streamed-content-"), 32)})
	metadata = patchZIPUint32(t, metadata, []byte("PK\x01\x02"), 24, 1)
	metadata = patchZIPUint32(t, metadata, []byte("PK\x07\x08"), 12, 1)
	unsafe := zipFixture(t, map[string][]byte{
		"../outside.jsp":   []byte("ignored"),
		"safe/Shell.class": requestClass,
	})
	collisionMalicious := archiveEntryFixture{name: "x/../Shell.class", data: requestClass, method: zip.Deflate}
	collisionBenign := archiveEntryFixture{name: "Shell.class", data: benignClass, method: zip.Deflate}
	collisionSource := archiveEntryFixture{name: "safe.jsp", data: []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), method: zip.Deflate}
	encryptedBase := zipFixtureOrdered(t, []archiveEntryFixture{{name: "bad.jsp", data: []byte("x"), method: zip.Store}})

	type fixture struct {
		name string
		data []byte
		opts Options
		ctx  context.Context
	}
	defaults := DefaultOptions()
	withLimits := func(set func(*Limits)) Options {
		opts := DefaultOptions()
		set(&opts.Limits)
		return opts
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	fixtures := []fixture{
		{"unsafe-paths", unsafe, defaults, context.Background()},
		{"unsafe-paths-nested", zipFixture(t, map[string][]byte{"WEB-INF/lib/payload.jar": unsafe}), defaults, context.Background()},
		{"normalized-collision-a", zipFixtureOrdered(t, []archiveEntryFixture{collisionMalicious, collisionBenign, collisionSource}), defaults, context.Background()},
		{"normalized-collision-b", zipFixtureOrdered(t, []archiveEntryFixture{collisionBenign, collisionMalicious, collisionSource}), defaults, context.Background()},
		{"crc-corruption", corrupt, defaults, context.Background()},
		{"encrypted", patchZIPFlags(t, encryptedBase, 1), defaults, context.Background()},
		{"unsupported-method", patchZIPMethod(t, encryptedBase, 99), defaults, context.Background()},
		{"zip64", zip64Fixture(t, "large.jsp", []byte("small"), uint64(1)<<32+5), withLimits(func(l *Limits) { l.MaxEntryBytes = 16 }), context.Background()},
		{"entry-budget", zipFixture(t, map[string][]byte{"a.txt": nil, "b.txt": nil}), withLimits(func(l *Limits) { l.MaxArchiveEntries = 1 }), context.Background()},
		{"entry-expanded-budget", zipFixture(t, map[string][]byte{"large.jsp": bytes.Repeat([]byte("x"), 32)}), withLimits(func(l *Limits) { l.MaxEntryBytes = 16 }), context.Background()},
		{"entry-compressed-budget", zipFixtureOrdered(t, []archiveEntryFixture{{name: "large.jsp", data: bytes.Repeat([]byte("x"), 32), method: zip.Store}}), withLimits(func(l *Limits) { l.MaxCompressedEntryBytes = 16 }), context.Background()},
		{"archive-expanded-budget", zipFixture(t, map[string][]byte{"a.jsp": bytes.Repeat([]byte("x"), 12), "b.jsp": bytes.Repeat([]byte("y"), 12)}), withLimits(func(l *Limits) { l.MaxEntryBytes = 16; l.MaxArchiveBytes = 20 }), context.Background()},
		{"ratio-budget", zipFixture(t, map[string][]byte{"large.jsp": ratioData}), withLimits(func(l *Limits) { l.CompressionRatioFloor = 1; l.MaxCompressionRatio = 2 }), context.Background()},
		{"depth-budget", zipFixture(t, map[string][]byte{"outer.jar": doubleNested}), withLimits(func(l *Limits) { l.MaxNestedDepth = 1 }), context.Background()},
		{"class-budget", zipFixture(t, map[string][]byte{"a/Shell.class": requestClass, "b/Other.class": fixtureClass(t, "branch_join")}), withLimits(func(l *Limits) { l.MaxClasses = 1 }), context.Background()},
		{"retained-class-budget", zipFixture(t, map[string][]byte{"Shell.class": requestClass}), withLimits(func(l *Limits) { l.MaxRetainedClassBytes = int64(len(requestClass) - 1) }), context.Background()},
		{"streamed-entry-budget", metadata, withLimits(func(l *Limits) { l.MaxEntryBytes = 64 }), context.Background()},
		{"streamed-archive-budget", metadata, withLimits(func(l *Limits) { l.MaxEntryBytes = 1024; l.MaxArchiveBytes = 64 }), context.Background()},
		{"nested-entry-budget", zipFixture(t, map[string][]byte{"WEB-INF/lib/payload.jar": zipFixture(t, map[string][]byte{"Shell.class": requestClass, "resource.txt": []byte("x")})}), withLimits(func(l *Limits) { l.MaxArchiveEntries = 2 }), context.Background()},
		{"nested-class-budget", zipFixture(t, map[string][]byte{"WEB-INF/classes/Benign.class": benignClass, "WEB-INF/lib/payload.jar": zipFixture(t, map[string][]byte{"Shell.class": requestClass})}), withLimits(func(l *Limits) { l.MaxClasses = 1 }), context.Background()},
		{"nested-retained-budget", zipFixture(t, map[string][]byte{"WEB-INF/classes/Benign.class": benignClass, "WEB-INF/lib/payload.jar": zipFixture(t, map[string][]byte{"Shell.class": requestClass})}), withLimits(func(l *Limits) { l.MaxRetainedClassBytes = int64(max(len(benignClass), len(requestClass))) }), context.Background()},
		{"cancelled", zipFixture(t, map[string][]byte{"Shell.class": requestClass}), defaults, cancelled},
	}
	memberWant := map[string]string{
		"unsafe-paths":            "3adeb69d7f7ef79c706ebd7fe817b31246a8aa16a50bca07a8ddbd1096d3b7fa",
		"unsafe-paths-nested":     "fbd421a92be174009edf2cd847a9d7595e7d56ef4cb2114d67d993a7b53ff7b2",
		"normalized-collision-a":  "13ea52902abf97e12dbafe1283d2b09ddc87a0baff8a0974e3d5a1d12dd5612f",
		"normalized-collision-b":  "42191df9f9871d4a96421ebb930c89f0e107547241debe65ad4b02dc8720841e",
		"crc-corruption":          "30ad7accdda7ca595708164dafc1dbcf3c83b685870bb7c8ab1aed964887b2cb",
		"encrypted":               "31d0adf140e7dd9d4e2c79a3b0aaae9b052fbba7bed30f15acc05a62dcb0b2b0",
		"unsupported-method":      "8d0303d741b59ef2ba9c482894a2fe5f72cdc6b991e6146da0c5889943cdb8b3",
		"zip64":                   "7e322476d6aa9b2c9f59964a4e14bd3e7ab5748cc90375c5d8c41484890ee0a0",
		"entry-budget":            "637f960888638bc3e0ce2b583a3d9c4146ad317b369a45eff84eb8a8894d0210",
		"entry-expanded-budget":   "8cb0e4ff6cf6560d6add6daceacf7720872d80c08350daff1699080afe1bb4ae",
		"entry-compressed-budget": "5345bb5cfdb618b8c09a63fdd49da85de6bcf814d75a2657c1fdfc3ceb4766c3",
		"archive-expanded-budget": "84f4a9fd67d14c3e8190862ed513019782712b3b0f2ee827d8113e3b847a25cc",
		"ratio-budget":            "1ecab06d6ddf53612e6924a66a2e4432d09a6ac38f0f083992f9371de3899ece",
		"depth-budget":            "1b180ca5f3e4b1d18bfd64108fb4e2c6141929d2640d945615281483cd8918c9",
		"class-budget":            "342a8c3910f4ea3041164a12d60ea97497cbbd5a5f56d7042b02ff9419e17bc8",
		"retained-class-budget":   "86e3dc8acca8f003ba81a49ba75c4c0538de65f9113208b3c8dd15fbde0e3acc",
		"streamed-entry-budget":   "c25ccc9d732514b03814fdf26f3d522349cd8c5a7d0a41cfcb024388732afee0",
		"streamed-archive-budget": "60c50cd5b834581640796bc851777ed8c77d646bf2e9041383ce540ae9ad316d",
		"nested-entry-budget":     "90cb7264b672c9617874aedc115e943ef39f1e0c7b4385492178f91a4406eb24",
		"nested-class-budget":     "4ab8eef24c453accfa66105e1bd853b40f83fb8f0e9ab5c879ad4c7df50ae7e1",
		"nested-retained-budget":  "769f9ef50b2d6ad8b742b89b0dcd8e52fe44f5d276f04248545e740da04ce16b",
		"cancelled":               "469f8dd11d1d95c38bfb047278f1a4e82aba80d8c990237d6a37fb636e1fc61d",
	}
	publicChangedWant := map[string]string{
		"unsafe-paths":        "33b546a42ede7172650f4f109fdf665ffe87d93a01875d20400efac4bfdf4867",
		"unsafe-paths-nested": "6e742b9a44fe4cc43c7d075c525c58ba920083588b1aab0d016eeb4a809b00c2",
		"encrypted":           "b3c8eabaa0506ee2f579054449cf9041e2571932f3479409cd14b51ea433d570",
		"unsupported-method":  "f0b78995b0adaa9dde16e1d3847f0fec353eb22d4cfc08d9f444a6eb152862a6",
	}
	// The original fixed hashes pin the shared member scanner below the new
	// local-header gate. Public hashes must remain identical unless the gate's
	// fail-closed policy intentionally changes the result.
	for _, tc := range fixtures {
		var memberResult Result
		if tc.name == "unsafe-paths-nested" {
			memberResult = analyzeLegacyNestedFixtureForEquivalence(t, tc.name+".war", unsafe, tc.opts)
		} else {
			source := bytes.NewReader(tc.data)
			archive, err := zip.NewReader(source, int64(len(tc.data)))
			if (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || archive == nil {
				t.Fatalf("open %s fixture: %v", tc.name, err)
			}
			memberResult = analyzeArchiveFiles(tc.ctx, tc.name+".war", archive.File, tc.opts, parseClass)
		}
		encoded, err := json.Marshal(memberResult)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		got := hex.EncodeToString(digest[:])
		if got != memberWant[tc.name] {
			t.Errorf("%s member=%s", tc.name, got)
		}

		publicResult := AnalyzeArtifactContext(tc.ctx, tc.name+".war", tc.data, tc.opts)
		encoded, err = json.Marshal(publicResult)
		if err != nil {
			t.Fatal(err)
		}
		digest = sha256.Sum256(encoded)
		got = hex.EncodeToString(digest[:])
		publicWant := memberWant[tc.name]
		if changed, ok := publicChangedWant[tc.name]; ok {
			publicWant = changed
		}
		if got != publicWant {
			t.Errorf("%s public=%s result=%+v", tc.name, got, publicResult)
		}
	}
}

func analyzeLegacyNestedFixtureForEquivalence(t *testing.T, outer string, data []byte, opts Options) Result {
	t.Helper()
	source := bytes.NewReader(data)
	archive, err := zip.NewReader(source, int64(len(data)))
	if (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || archive == nil {
		t.Fatalf("open nested legacy fixture: %v", err)
	}
	opts = normalizeOptions(opts)
	results := newBoundedResults(opts.Limits.MaxFindings)
	digest := sha256.Sum256(data)
	scanner := &archiveScanner{
		ctx: context.Background(), outer: outer, opts: opts, parser: parseClass,
		budget: &archiveBudget{
			entries: 1, expanded: int64(len(data)),
			digests: map[[sha256.Size]byte]struct{}{digest: struct{}{}},
		},
		classes: make(map[string]*classModel),
		results: results,
	}
	scanner.scan(archive.File, logicalMemberPath(outer, "WEB-INF/lib/payload.jar"), 1)
	if len(scanner.classes) != 0 {
		results.addResult(analyzeClassesContext(context.Background(), outer, scanner.classes, opts), outer)
	}
	return results.finish()
}

func TestArchiveSharedSafetyMigrationPreservesValidFixtureResults(t *testing.T) {
	requestClass := fixtureClass(t, "request_exec")
	entries := artifactFixtures["request_exec_helper"](t)
	entryClass, _ := classBytes(t, entries[0].Spec)
	helperClass, _ := classBytes(t, entries[1].Spec)
	nested := zipFixture(t, map[string][]byte{"x/Shell.class": requestClass})
	summaryNested := zipFixture(t, map[string][]byte{"fixture/Helper.class": helperClass})
	classEntry := archiveEntryFixture{name: "a/Shell.class", data: requestClass, method: zip.Deflate}
	sourceEntry := archiveEntryFixture{
		name: "z/shell.jsp", method: zip.Deflate,
		data: []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`),
	}

	type fixture struct {
		name string
		path string
		data []byte
	}
	fixtures := []fixture{
		{"valid-class", "app.jar", zipFixture(t, map[string][]byte{"x/Shell.class": requestClass})},
		{"valid-class-source", "app.war", zipFixture(t, map[string][]byte{
			"WEB-INF/classes/x/Shell.class": requestClass,
			"views/shell.jsp":               sourceEntry.data,
		})},
		{"valid-nested", "app.war", zipFixture(t, map[string][]byte{"WEB-INF/lib/payload.jar": nested})},
		{"valid-cross-nested-summary", "app.war", zipFixture(t, map[string][]byte{
			"WEB-INF/classes/fixture/Entry.class": entryClass,
			"WEB-INF/lib/helper.jar":              summaryNested,
		})},
		{"valid-duplicate-content", "dupe.jar", zipFixture(t, map[string][]byte{
			"a/Shell.class": requestClass,
			"b/Shell.class": requestClass,
		})},
		{"valid-order-a", "order.war", zipFixtureOrdered(t, []archiveEntryFixture{sourceEntry, classEntry})},
		{"valid-order-b", "order.war", zipFixtureOrdered(t, []archiveEntryFixture{classEntry, sourceEntry})},
		{"valid-empty", "empty.jar", zipFixture(t, map[string][]byte{})},
	}
	want := map[string]string{
		"valid-class":                "3ec18adec674ea16090cce90f83c484f27ad053f15fcecfc026f8b7c4b078669",
		"valid-class-source":         "2ca78c9d7d25c8a3ae05d9dd8e6fc08ce3306db7b681f0e6f8e40090d90b2e90",
		"valid-nested":               "6cb3a8b9a8586c3cb8f534bd5c46b488ec77fb4b5a22c7f2ea91d73033abbd89",
		"valid-cross-nested-summary": "7b9b2dda99cb9ebc2760ba6d36668f63f8a831cf37550afc22508080f34e4378",
		"valid-duplicate-content":    "47c464b1efbc389202a3a0146f6ad7a87c468525d075d3b821cd2ef93d97bca4",
		"valid-order-a":              "ba6121827092484334ea73ec94f5a81c1a25c9c97ad4443cf30a36519cfbe1b1",
		"valid-order-b":              "ba6121827092484334ea73ec94f5a81c1a25c9c97ad4443cf30a36519cfbe1b1",
		"valid-empty":                "a75d2af2354235c6b2033a9bbf6c7c9e189b02af2c9c7a8a8aa7bab2a5984285",
	}

	for _, tc := range fixtures {
		result := AnalyzeArtifact(tc.path, tc.data, DefaultOptions())
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		got := hex.EncodeToString(digest[:])
		if got != want[tc.name] {
			t.Errorf("%s=%s", tc.name, got)
		}
	}
}

func TestAnalyzePathStreamsArchiveAndLooseArtifacts(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "app.war")
	archive := zipFixture(t, map[string][]byte{"WEB-INF/classes/Shell.class": fixtureClass(t, "request_exec")})
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveResult := AnalyzePath(context.Background(), archivePath, DefaultOptions())
	finding := findingByRule(archiveResult.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.ArtifactPath != archivePath {
		t.Fatalf("archive result=%+v", archiveResult)
	}

	classPath := writeFixtureClass(t, root, "Loose.class", "request_exec")
	classResult := AnalyzePath(context.Background(), classPath, DefaultOptions())
	if finding := findingByRule(classResult.Findings, "javadisk:class-request-exec"); finding == nil || finding.ArtifactPath != classPath {
		t.Fatalf("class result=%+v", classResult)
	}

	opts := DefaultOptions()
	opts.Limits.MaxArtifactBytes = 1
	if result := AnalyzePath(context.Background(), classPath, opts); !hasDiagnosticCode(result.Diagnostics, diagAnalysisBudget) {
		t.Fatalf("overflow result=%+v", result)
	}
}

func TestAnalyzePathsGroupsClassesWithinExplodedApplication(t *testing.T) {
	root := t.TempDir()
	paths := writeArtifactFixture(t, root, "app/WEB-INF/classes", "request_exec_helper")
	res := AnalyzePaths(context.Background(), paths, DefaultOptions())
	finding := findingByRule(res.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 || !containsString(paths, finding.ArtifactPath) {
		t.Fatalf("result=%+v paths=%v", res, paths)
	}
}

func TestAnalyzePathsDoesNotSummarizeAcrossExplodedApplications(t *testing.T) {
	root := t.TempDir()
	entries := artifactFixtures["request_exec_helper"](t)
	entryData, _ := classBytes(t, entries[0].Spec)
	helperData, _ := classBytes(t, entries[1].Spec)
	paths := []string{
		writeRawClass(t, root, "a/WEB-INF/classes/fixture/Entry.class", entryData),
		writeRawClass(t, root, "b/WEB-INF/classes/fixture/Helper.class", helperData),
	}
	res := AnalyzePaths(context.Background(), paths, DefaultOptions())
	if findingByRule(res.Findings, "javadisk:class-request-exec") != nil {
		t.Fatalf("cross-application flow reported: %+v", res)
	}
}

func TestAnalyzePathsMalformedMemberPreservesSiblingsAndSharedClassBudget(t *testing.T) {
	root := t.TempDir()
	good := writeFixtureClass(t, root, "a/WEB-INF/classes/Good.class", "request_exec")
	bad := writeRawClass(t, root, "a/WEB-INF/classes/Bad.class", []byte("bad"))
	other := writeFixtureClass(t, root, "b/WEB-INF/classes/Other.class", "branch_join")
	opts := DefaultOptions()
	opts.Limits.MaxClasses = 2
	res := AnalyzePaths(context.Background(), []string{other, bad, good}, opts)
	if findingByRule(res.Findings, "javadisk:class-request-exec") == nil || !hasDiagnosticCode(res.Diagnostics, diagClassMalformed) || !hasDiagnosticCode(res.Diagnostics, diagAnalysisBudget) {
		t.Fatalf("result=%+v", res)
	}
}

func TestAnalyzePathsReviewCancellationDuringReadIsCountedOnce(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		writeFixtureClass(t, root, "a/First.class", "request_exec"),
		writeFixtureClass(t, root, "b/Second.class", "request_exec"),
	}
	ctx := newStepCancelContext(3)
	result := AnalyzePaths(ctx, paths, DefaultOptions())
	if len(result.Findings) != 0 || diagnosticCount(result.Diagnostics, diagCancelled) != 1 {
		t.Fatalf("calls=%d result=%+v", ctx.calls, result)
	}
}

func TestAnalyzePathsReviewChecksCancellationBetweenReadAndParse(t *testing.T) {
	root := t.TempDir()
	path := writeRawClass(t, root, "Malformed.class", []byte("malformed"))
	ctx := newStepCancelContext(5)
	result := AnalyzePaths(ctx, []string{path}, DefaultOptions())
	if hasDiagnosticCode(result.Diagnostics, diagClassMalformed) || diagnosticCount(result.Diagnostics, diagCancelled) != 1 {
		t.Fatalf("calls=%d result=%+v", ctx.calls, result)
	}
}

func TestAnalyzePathsReviewReportsCancellationAfterSourceSibling(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "shell.jsp")
	if err := os.WriteFile(path, []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := newStepCancelContext(7)
	result := AnalyzePaths(ctx, []string{path}, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:request-exec") == nil || diagnosticCount(result.Diagnostics, diagCancelled) != 1 {
		t.Fatalf("calls=%d result=%+v", ctx.calls, result)
	}
}

func FuzzAnalyzeArchiveNeverPanics(f *testing.F) {
	f.Add([]byte("not a zip"))
	f.Add(zipFixtureForFuzz(f, "Shell.class", []byte("bad")))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = AnalyzeArtifactContext(context.Background(), "fuzz.war", data, DefaultOptions())
	})
}

func zipFixtureForFuzz(tb testing.TB, name string, data []byte) []byte {
	tb.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	part, err := writer.Create(name)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		tb.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		tb.Fatal(err)
	}
	return buffer.Bytes()
}

func writeRawClass(t *testing.T, root, relative string, data []byte) string {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return full
}

func corruptStoredEntry(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	reader, err := zip.NewReader(bytes.NewReader(result), int64(len(result)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		if file.Name != name {
			continue
		}
		offset, err := file.DataOffset()
		if err != nil {
			t.Fatal(err)
		}
		result[offset] ^= 0xff
		return result
	}
	t.Fatalf("entry %q not found", name)
	return nil
}

func patchZIPFlags(t *testing.T, data []byte, flags uint16) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	if !patchZIPField(result, []byte("PK\x03\x04"), 6, flags) || !patchZIPField(result, []byte("PK\x01\x02"), 8, flags) {
		t.Fatal("ZIP headers not found")
	}
	return result
}

func patchZIPMethod(t *testing.T, data []byte, method uint16) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	if !patchZIPField(result, []byte("PK\x03\x04"), 8, method) || !patchZIPField(result, []byte("PK\x01\x02"), 10, method) {
		t.Fatal("ZIP headers not found")
	}
	return result
}

func patchZIPLocalMethod(t *testing.T, data []byte, method uint16) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	if !patchZIPField(result, []byte("PK\x03\x04"), 8, method) {
		t.Fatal("ZIP local header not found")
	}
	return result
}

func patchZIPField(data, signature []byte, field int, value uint16) bool {
	index := bytes.Index(data, signature)
	if index < 0 || index+field+2 > len(data) {
		return false
	}
	binary.LittleEndian.PutUint16(data[index+field:index+field+2], value)
	return true
}

func patchZIPUint32(t *testing.T, data, signature []byte, field int, value uint32) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	index := bytes.Index(result, signature)
	if index < 0 || index+field+4 > len(result) {
		t.Fatal("ZIP header field not found")
	}
	binary.LittleEndian.PutUint32(result[index+field:index+field+4], value)
	return result
}

func assertUnsafeLocalArchiveRejected(t *testing.T, result Result) {
	t.Helper()
	if len(result.Findings) != 0 ||
		!diagnosticHasDetail(result.Diagnostics, diagArtifactRead, "unsafe local ZIP entry name") {
		t.Fatalf("result=%+v", result)
	}
}

type stepCancelContext struct {
	calls    int
	cancelAt int
	done     chan struct{}
}

func newStepCancelContext(cancelAt int) *stepCancelContext {
	return &stepCancelContext{cancelAt: cancelAt, done: make(chan struct{})}
}

func (ctx *stepCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *stepCancelContext) Done() <-chan struct{}       { return ctx.done }
func (ctx *stepCancelContext) Value(any) any               { return nil }

func (ctx *stepCancelContext) Err() error {
	ctx.calls++
	if ctx.calls < ctx.cancelAt {
		return nil
	}
	select {
	case <-ctx.done:
	default:
		close(ctx.done)
	}
	return context.Canceled
}

func diagnosticHasDetail(diagnostics []Diagnostic, code, detail string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && strings.Contains(diagnostic.Detail, detail) {
			return true
		}
	}
	return false
}

func diagnosticCount(diagnostics []Diagnostic, code string) int {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return diagnostic.Count
		}
	}
	return 0
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
