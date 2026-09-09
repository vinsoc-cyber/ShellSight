package javadisk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"testing"
)

var benchmarkResultSink Result

func benchmarkClass(name string, methods int, code []byte) []byte {
	pool := newConstantPoolBuilder()
	thisClass := pool.u2Entry(cpClass, pool.utf8(name))
	superClass := pool.u2Entry(cpClass, pool.utf8("java/lang/Object"))
	codeName := pool.utf8("Code")
	methodBytes := make([][]byte, 0, methods)
	for i := 0; i < methods; i++ {
		name := pool.utf8(fmt.Sprintf("run%d", i))
		descriptor := pool.utf8("()V")
		payload := append(u2Bytes(2), u2Bytes(1)...)
		payload = append(payload, u4Bytes(uint32(len(code)))...)
		payload = append(payload, code...)
		payload = append(payload, 0, 0, 0, 0)
		methodBytes = append(methodBytes, memberFixture(0x0009, name, descriptor, attributeFixture(codeName, payload)))
	}
	data := finishClass(0, 49, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0)
	data = append(data, u2Bytes(uint16(len(methodBytes)))...)
	for _, method := range methodBytes {
		data = append(data, method...)
	}
	data = append(data, 0, 0)
	return data
}

func benchmarkPreflight(b *testing.B, path string, data []byte, opts Options) {
	b.Helper()
	result := AnalyzeArtifact(path, data, opts)
	if len(result.Diagnostics) != 0 {
		b.Fatalf("benchmark fixture %s produced diagnostics: %+v", path, result.Diagnostics)
	}
	benchmarkResultSink = result
}

func benchmarkJoinCode(branches int) []byte {
	code := []byte{0x03, 0x3b} // iconst_0; istore_0
	for i := 0; i < branches; i++ {
		code = append(code,
			0x1a,             // iload_0
			0x99, 0x00, 0x05, // ifeq +5
			0x04, // iconst_1
			0x3b, // istore_0
		)
	}
	return append(code, 0xb1)
}

func benchmarkZip(tb testing.TB, entries map[string][]byte) []byte {
	tb.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range names {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			tb.Fatalf("create benchmark ZIP entry %q: %v", name, err)
		}
		if _, err := part.Write(entries[name]); err != nil {
			tb.Fatalf("write benchmark ZIP entry %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		tb.Fatalf("close benchmark ZIP: %v", err)
	}
	return buffer.Bytes()
}

func benchmarkRequireDistinctClassBytes(tb testing.TB, entries map[string][]byte) {
	tb.Helper()
	seen := make(map[[sha256.Size]byte]string)
	for path, data := range entries {
		if !strings.HasSuffix(path, ".class") {
			continue
		}
		sum := sha256.Sum256(data)
		if previous, ok := seen[sum]; ok {
			tb.Fatalf("benchmark class entries %s and %s have identical bytes", previous, path)
		}
		seen[sum] = path
	}
}

func BenchmarkAnalyzeSmallClass(b *testing.B) {
	classData := benchmarkClass("bench/Small", 1, []byte{0xb1})
	opts := DefaultOptions()
	benchmarkPreflight(b, "small.class", classData, opts)
	b.ReportAllocs()
	b.SetBytes(int64(len(classData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkResultSink = AnalyzeArtifact("small.class", classData, opts)
	}
}

func BenchmarkAnalyzeLargeClassSet(b *testing.B) {
	classData := benchmarkClass("bench/Large", 200, []byte{0xb1})
	opts := DefaultOptions()
	benchmarkPreflight(b, "large.class", classData, opts)
	b.ReportAllocs()
	b.SetBytes(int64(len(classData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkResultSink = AnalyzeArtifact("large.class", classData, opts)
	}
}

func BenchmarkAnalyzeBenignJar(b *testing.B) {
	entries := make(map[string][]byte)
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("bench/C%03d", i)
		entries[fmt.Sprintf("WEB-INF/classes/%s.class", name)] = benchmarkClass(name, 4, []byte{0xb1})
	}
	benchmarkRequireDistinctClassBytes(b, entries)
	jar := benchmarkZip(b, entries)
	opts := DefaultOptions()
	benchmarkPreflight(b, "benign.jar", jar, opts)
	b.ReportAllocs()
	b.SetBytes(int64(len(jar)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkResultSink = AnalyzeArtifact("benign.jar", jar, opts)
	}
}

func BenchmarkAnalyzeNestedWar(b *testing.B) {
	inner := benchmarkZip(b, map[string][]byte{
		"bench/Nested.class": benchmarkClass("bench/Nested", 20, []byte{0xb1}),
	})
	war := benchmarkZip(b, map[string][]byte{
		"WEB-INF/classes/bench/App.class": benchmarkClass("bench/App", 20, []byte{0xb1}),
		"WEB-INF/lib/nested.jar":          inner,
		"views/index.jsp":                 []byte(`<% out.print("ok"); %>`),
	})
	opts := DefaultOptions()
	benchmarkPreflight(b, "nested.war", war, opts)
	b.ReportAllocs()
	b.SetBytes(int64(len(war)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkResultSink = AnalyzeArtifact("nested.war", war, opts)
	}
}

func BenchmarkAnalyzeAdversarialJoins(b *testing.B) {
	classData := benchmarkClass("bench/Joins", 5, benchmarkJoinCode(80))
	opts := DefaultOptions()
	benchmarkPreflight(b, "joins.class", classData, opts)
	b.ReportAllocs()
	b.SetBytes(int64(len(classData)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkResultSink = AnalyzeArtifact("joins.class", classData, opts)
	}
}
