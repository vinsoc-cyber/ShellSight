package safearchive

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizePathRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../x", "/x", `\\server\share\x`, `C:\x`, "a\x00b"} {
		if normalized, err := NormalizePath(name); err == nil {
			t.Fatalf("NormalizePath(%q)=%q, nil", name, normalized)
		}
	}
	for name, want := range map[string]string{
		"a/b.jsp":    "a/b.jsp",
		`a\b.jsp`:    "a/b.jsp",
		"a/../b.jsp": "b.jsp",
	} {
		if got, err := NormalizePath(name); err != nil || got != want {
			t.Fatalf("NormalizePath(%q)=%q, %v want %q", name, got, err, want)
		}
	}
}

func TestReadZIPEntryRejectsGlobalBudgetOverflow(t *testing.T) {
	archive := testZIP(t, []testZIPEntry{{name: "a.jsp", method: zip.Store, data: []byte("inert")}})
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	total := int64(math.MaxInt64 - 1)
	_, err = ReadZIPEntry(context.Background(), reader.File[0], ZIPLimits{
		MaxCompressedBytes: 1 << 20,
		MaxExpandedBytes:   1 << 20,
		MaxTotalBytes:      math.MaxInt64,
		MaxRatio:           200,
		RatioFloor:         64 << 10,
	}, &total)
	if err == nil || !IsBudgetError(err) || !strings.Contains(err.Error(), "archive expanded byte limit") {
		t.Fatalf("total=%d error=%v", total, err)
	}
}

func TestPrepareZIPRejectsCollisionsAndUnsafeMetadataDeterministically(t *testing.T) {
	archive := testZIP(t, []testZIPEntry{
		{name: "z.jsp", method: zip.Deflate, data: []byte("inert-z")},
		{name: "a/../x.jsp", method: zip.Deflate, data: []byte("inert-one")},
		{name: "x.jsp", method: zip.Deflate, data: []byte("inert-two")},
		{name: "safe.jsp", method: zip.Deflate, data: []byte("inert-safe")},
	})
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	first := PrepareZIP(reader.File, func(name string) int {
		if strings.HasPrefix(name, "safe") {
			return 0
		}
		return 1
	})
	second := PrepareZIP([]*zip.File{reader.File[3], reader.File[2], reader.File[1], reader.File[0]}, func(name string) int {
		if strings.HasPrefix(name, "safe") {
			return 0
		}
		return 1
	})
	if !reflect.DeepEqual(zipEntrySummary(first), zipEntrySummary(second)) {
		t.Fatalf("first=%v second=%v", zipEntrySummary(first), zipEntrySummary(second))
	}
	want := []string{"safe.jsp", "x.jsp:duplicate normalized archive entry path rejected", "z.jsp"}
	if got := zipEntrySummary(first); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries=%v want=%v", got, want)
	}
}

func TestCompressedCounterAndReadZIPEntryEnforceActualBytesAndIntegrity(t *testing.T) {
	payload := bytes.Repeat([]byte("inert-compressed-content"), 128)
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

	counter := NewCompressedCounter(bytes.NewReader(compressed.Bytes()), 32)
	inflater := flate.NewReader(counter)
	defer inflater.Close()
	_, err = io.Copy(io.Discard, inflater)
	if !errors.Is(err, ErrCompressedEntryLimit) || counter.BytesRead() != 33 {
		t.Fatalf("raw bytes=%d err=%v", counter.BytesRead(), err)
	}

	archive := testZIP(t, []testZIPEntry{{name: "a.jsp", method: zip.Deflate, data: []byte("inert")}})
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	got, err := ReadZIPEntry(context.Background(), reader.File[0], ZIPLimits{
		MaxCompressedBytes: 1 << 20,
		MaxExpandedBytes:   1 << 20,
		MaxTotalBytes:      1 << 20,
		MaxRatio:           200,
		RatioFloor:         64 << 10,
	}, &total)
	if err != nil || string(got) != "inert" || total != 5 {
		t.Fatalf("data=%q total=%d err=%v", got, total, err)
	}
}

func TestCompressedCounterHandlesMaxInt64Limit(t *testing.T) {
	counter := NewCompressedCounter(strings.NewReader("inert"), math.MaxInt64)
	got, err := io.ReadAll(counter)
	if err != nil || string(got) != "inert" || counter.BytesRead() != 5 {
		t.Fatalf("data=%q bytes=%d error=%v", got, counter.BytesRead(), err)
	}
}

func TestReadZIPEntryStopsCompressedDrainOnCancellation(t *testing.T) {
	const (
		tailSize    = 1 << 20
		cancelDelay = 64 << 10
	)
	data, dataOffset, deflateSize := testZIPWithDeflateTrailingData(t, tailSize)
	ctx, cancel := context.WithCancel(context.Background())
	readerAt := &cancelingZIPReaderAt{
		data: data, cancel: cancel,
		cancelAt: dataOffset + deflateSize + cancelDelay,
	}
	archive, err := zip.NewReader(readerAt, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	readerAt.armed = true
	total := int64(0)
	_, err = ReadZIPEntry(ctx, archive.File[0], ZIPLimits{
		MaxCompressedBytes: int64(len(data)),
		MaxExpandedBytes:   1 << 20,
		MaxTotalBytes:      1 << 20,
		MaxRatio:           math.MaxInt64,
		RatioFloor:         math.MaxInt64,
	}, &total)
	if err != context.Canceled {
		t.Fatalf("error=%v", err)
	}
	maximumRead := readerAt.cancelAt - dataOffset + 32<<10
	if readerAt.bytesRead > maximumRead {
		t.Fatalf("compressed bytes after cancellation=%d bound=%d tail=%d", readerAt.bytesRead, maximumRead, tailSize)
	}
}

type testZIPEntry struct {
	name   string
	method uint16
	data   []byte
}

func testZIP(t testing.TB, entries []testZIPEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: entry.method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func testZIPWithDeflateTrailingData(t testing.TB, tailSize int) ([]byte, int64, int64) {
	t.Helper()
	data := testZIP(t, []testZIPEntry{{
		name: "a.jsp", method: zip.Deflate, data: bytes.Repeat([]byte("inert"), 1024),
	}})
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	file := archive.File[0]
	dataOffset, err := file.DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	deflateSize := int64(file.CompressedSize64)
	insertAt := int(dataOffset + deflateSize)
	eocd := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if eocd < 0 {
		t.Fatal("ZIP end record not found")
	}
	centralOffset := int(binary.LittleEndian.Uint32(data[eocd+16 : eocd+20]))
	tail := make([]byte, tailSize)
	result := make([]byte, 0, len(data)+len(tail))
	result = append(result, data[:insertAt]...)
	result = append(result, tail...)
	result = append(result, data[insertAt:]...)
	newCentralOffset := centralOffset + tailSize
	newEOCD := eocd + tailSize
	binary.LittleEndian.PutUint32(result[newCentralOffset+20:newCentralOffset+24], uint32(deflateSize)+uint32(tailSize))
	binary.LittleEndian.PutUint32(result[newEOCD+16:newEOCD+20], uint32(newCentralOffset))
	return result, dataOffset, deflateSize
}

type cancelingZIPReaderAt struct {
	data      []byte
	cancel    context.CancelFunc
	cancelAt  int64
	armed     bool
	bytesRead int64
}

func (reader *cancelingZIPReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	n := copy(buffer, reader.data[offset:])
	if reader.armed {
		reader.bytesRead += int64(n)
		if offset+int64(n) >= reader.cancelAt {
			reader.cancel()
		}
	}
	if offset+int64(n) == int64(len(reader.data)) {
		return n, io.EOF
	}
	return n, nil
}

func zipEntrySummary(entries []ZIPEntry) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		value := entry.Name
		if entry.Err != nil {
			value += ":" + entry.Err.Error()
		}
		result = append(result, value)
	}
	return result
}
