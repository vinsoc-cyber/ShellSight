package safearchive

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

const (
	testLocalHeaderSignature = 0x04034b50
	testCentralSignature     = 0x02014b50
	testDescriptorSignature  = 0x08074b50
	testEOCDSignature        = 0x06054b50
	testZIP64ExtraID         = 0x0001
)

type rawZIPEntry struct {
	localName           []byte
	centralName         []byte
	data                []byte
	localExtra          []byte
	centralExtra        []byte
	descriptor          []byte
	localFlags          uint16
	centralFlags        uint16
	localMethod         uint16
	centralMethod       uint16
	localCRC            uint32
	centralCRC          uint32
	localCompressed     uint32
	centralCompressed   uint32
	localUncompressed   uint32
	centralUncompressed uint32
	localOffsetOverride *uint32
}

type rawZIPLayout struct {
	localOffsets []int
	dataOffsets  []int
	central      int
	eocd         int
}

func TestValidateZIPLocalHeadersAcceptsValidControls(t *testing.T) {
	descriptor := descriptor32(true, crc32.ChecksumIEEE([]byte("inert")), 5, 5)
	unsignedDescriptor := descriptor32(false, crc32.ChecksumIEEE([]byte("inert")), 5, 5)
	zip64Extra := zip64LocalExtra(5, 5)
	tests := []struct {
		name  string
		entry rawZIPEntry
	}{
		{name: "ordinary", entry: ordinaryRawZIPEntry("safe.jsp", []byte("inert"))},
		{name: "signed-descriptor", entry: descriptorRawZIPEntry("safe.jsp", []byte("inert"), descriptor)},
		{name: "unsigned-descriptor", entry: descriptorRawZIPEntry("safe.jsp", []byte("inert"), unsignedDescriptor)},
		{name: "zip64-descriptor", entry: func() rawZIPEntry {
			entry := descriptorRawZIPEntry("safe.jsp", []byte("inert"), descriptor64(true, crc32.ChecksumIEEE([]byte("inert")), 5, 5))
			entry.centralCompressed = ^uint32(0)
			entry.centralUncompressed = ^uint32(0)
			entry.centralExtra = zip64Extra
			return entry
		}()},
		{name: "zip64", entry: func() rawZIPEntry {
			entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
			entry.localCompressed = ^uint32(0)
			entry.localUncompressed = ^uint32(0)
			entry.centralCompressed = ^uint32(0)
			entry.centralUncompressed = ^uint32(0)
			entry.localExtra = zip64Extra
			entry.centralExtra = zip64Extra
			return entry
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := buildRawZIP(t, []rawZIPEntry{test.entry})
			if err := validateRawZIP(t, data); err != nil {
				t.Fatalf("ValidateZIPLocalHeaders() error = %v", err)
			}
		})
	}

	t.Run("prepended-archive", func(t *testing.T) {
		data, _ := buildRawZIP(t, []rawZIPEntry{ordinaryRawZIPEntry("safe.jsp", []byte("inert"))})
		data = append([]byte("inert-launcher-prefix\n"), data...)
		if err := validateRawZIP(t, data); err != nil {
			t.Fatalf("ValidateZIPLocalHeaders() error = %v", err)
		}
	})
}

func TestValidateZIPLocalHeadersRejectsLocalUnsafeNames(t *testing.T) {
	tests := []struct {
		name      string
		localName string
	}{
		{name: "parent", localName: "../x.jsp"},
		{name: "absolute", localName: "/bad.jsp"},
		{name: "unc", localName: `\\host\x`},
		{name: "drive", localName: `C:\x.jsp`},
		{name: "backslash", localName: `a\b.jsp`},
		{name: "nul", localName: "a\x00b.jsp"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
			entry.localName = []byte(test.localName)
			assertLocalZIPError(t, entry, "unsafe local ZIP entry name")
		})
	}
}

func TestValidateZIPLocalHeadersRejectsLocalMetadataMismatches(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*rawZIPEntry)
	}{
		{name: "name", want: "name mismatch", edit: func(entry *rawZIPEntry) { entry.localName = []byte("other.jsp") }},
		{name: "encrypted", want: "encrypted", edit: func(entry *rawZIPEntry) { entry.localFlags |= 1 }},
		{name: "strong-encryption", want: "encrypted", edit: func(entry *rawZIPEntry) { entry.localFlags |= 1 << 6 }},
		{name: "flags", want: "flags mismatch", edit: func(entry *rawZIPEntry) { entry.localFlags |= 1 << 11 }},
		{name: "unsupported-method", want: "unsupported ZIP compression method", edit: func(entry *rawZIPEntry) { entry.localMethod = 99 }},
		{name: "method", want: "method mismatch", edit: func(entry *rawZIPEntry) { entry.localMethod = zip.Deflate }},
		{name: "crc", want: "CRC mismatch", edit: func(entry *rawZIPEntry) { entry.localCRC++ }},
		{name: "compressed-size", want: "compressed size mismatch", edit: func(entry *rawZIPEntry) { entry.localCompressed++ }},
		{name: "uncompressed-size", want: "uncompressed size mismatch", edit: func(entry *rawZIPEntry) { entry.localUncompressed++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
			test.edit(&entry)
			assertLocalZIPError(t, entry, test.want)
		})
	}
}

func TestValidateZIPLocalHeadersRejectsInvalidDataDescriptors(t *testing.T) {
	checksum := crc32.ChecksumIEEE([]byte("inert"))
	tests := []struct {
		name       string
		want       string
		descriptor []byte
		edit       func(*rawZIPEntry)
	}{
		{name: "missing", want: "data descriptor", descriptor: nil},
		{name: "truncated", want: "truncated data descriptor", descriptor: descriptor32(true, checksum, 5, 5)[:11]},
		{name: "crc", want: "data descriptor CRC mismatch", descriptor: descriptor32(true, checksum+1, 5, 5)},
		{name: "compressed-size", want: "data descriptor compressed size mismatch", descriptor: descriptor32(true, checksum, 6, 5)},
		{name: "uncompressed-size", want: "data descriptor uncompressed size mismatch", descriptor: descriptor32(true, checksum, 5, 6)},
		{name: "nonzero-local-crc", want: "data-descriptor local CRC", descriptor: descriptor32(true, checksum, 5, 5), edit: func(entry *rawZIPEntry) { entry.localCRC = checksum }},
		{name: "nonzero-local-size", want: "data-descriptor local sizes", descriptor: descriptor32(true, checksum, 5, 5), edit: func(entry *rawZIPEntry) { entry.localCompressed = 5 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := descriptorRawZIPEntry("safe.jsp", []byte("inert"), test.descriptor)
			if test.edit != nil {
				test.edit(&entry)
			}
			assertLocalZIPError(t, entry, test.want)
		})
	}

	t.Run("signature-ambiguity", func(t *testing.T) {
		entry := descriptorRawZIPEntry("safe.jsp", []byte("inert"), descriptor32(false, testDescriptorSignature, 5, 5))
		entry.centralCRC = testDescriptorSignature
		assertLocalZIPError(t, entry, "ambiguous data descriptor signature")
	})

	t.Run("descriptor-without-bit-3", func(t *testing.T) {
		entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
		entry.descriptor = descriptor32(true, checksum, 5, 5)
		assertLocalZIPError(t, entry, "unexpected data descriptor")
	})
}

func TestValidateZIPLocalHeadersRejectsInvalidZIP64Extras(t *testing.T) {
	valid := zip64LocalExtra(5, 5)
	truncated := appendField(nil, testZIP64ExtraID, append64(nil, 5))
	binary.LittleEndian.PutUint16(truncated[2:4], 16)
	duplicate := append(append([]byte(nil), valid...), valid...)
	tests := []struct {
		name  string
		want  string
		entry rawZIPEntry
	}{
		{name: "missing", want: "missing local ZIP64", entry: zip64RawZIPEntry(nil)},
		{name: "truncated", want: "truncated local ZIP64", entry: zip64RawZIPEntry(truncated)},
		{name: "duplicate", want: "duplicate local ZIP64", entry: zip64RawZIPEntry(duplicate)},
		{name: "uncompressed-mismatch", want: "ZIP64 uncompressed size mismatch", entry: zip64RawZIPEntry(zip64LocalExtra(6, 5))},
		{name: "compressed-mismatch", want: "ZIP64 compressed size mismatch", entry: zip64RawZIPEntry(zip64LocalExtra(5, 6))},
		{name: "unnecessary", want: "unnecessary local ZIP64", entry: func() rawZIPEntry {
			entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
			entry.localExtra = valid
			return entry
		}()},
		{name: "ambiguous-trailing-value", want: "ambiguous local ZIP64", entry: func() rawZIPEntry {
			entry := zip64RawZIPEntry(appendField(nil, testZIP64ExtraID, append64(append64(append64(nil, 5), 5), 0)))
			return entry
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertLocalZIPError(t, test.entry, test.want)
		})
	}

	t.Run("truncated-extra-field", func(t *testing.T) {
		entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
		entry.localExtra = []byte{0x55, 0x54, 0x08, 0x00, 0x01}
		assertLocalZIPError(t, entry, "truncated local extra field")
	})
}

func TestValidateZIPLocalHeadersRejectsOffsetsOverlapsAndTruncation(t *testing.T) {
	t.Run("duplicate-local-offset", func(t *testing.T) {
		first := ordinaryRawZIPEntry("same.jsp", []byte("one"))
		second := ordinaryRawZIPEntry("same.jsp", []byte("two"))
		zero := uint32(0)
		second.localOffsetOverride = &zero
		data, _ := buildRawZIP(t, []rawZIPEntry{first, second})
		assertRawZIPError(t, data, "duplicate local header offset")
	})

	t.Run("overlap", func(t *testing.T) {
		data := overlappingRawZIP(t)
		assertRawZIPError(t, data, "overlapping ZIP entry spans")
	})

	t.Run("out-of-range", func(t *testing.T) {
		data, layout := buildRawZIP(t, []rawZIPEntry{ordinaryRawZIPEntry("safe.jsp", []byte("inert"))})
		binary.LittleEndian.PutUint32(data[layout.central+42:layout.central+46], uint32(len(data)+1))
		assertRawZIPError(t, data, "local header offset out of range")
	})

	t.Run("truncated-fixed-header", func(t *testing.T) {
		entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
		entry.data = append(entry.data, make([]byte, 4)...)
		entry.localCompressed = uint32(len(entry.data))
		entry.localUncompressed = uint32(len(entry.data))
		entry.centralCompressed = uint32(len(entry.data))
		entry.centralUncompressed = uint32(len(entry.data))
		entry.localCRC = crc32.ChecksumIEEE(entry.data)
		entry.centralCRC = entry.localCRC
		data, layout := buildRawZIP(t, []rawZIPEntry{entry})
		offset := layout.central - 4
		binary.LittleEndian.PutUint32(data[offset:offset+4], testLocalHeaderSignature)
		binary.LittleEndian.PutUint32(data[layout.central+42:layout.central+46], uint32(offset))
		assertRawZIPError(t, data, "truncated local file header")
	})

	t.Run("truncated-variable-header", func(t *testing.T) {
		data, _ := buildRawZIP(t, []rawZIPEntry{ordinaryRawZIPEntry("safe.jsp", []byte("inert"))})
		binary.LittleEndian.PutUint16(data[26:28], ^uint16(0))
		assertRawZIPError(t, data, "truncated local file header name or extra")
	})

	t.Run("bad-signature", func(t *testing.T) {
		data, _ := buildRawZIP(t, []rawZIPEntry{ordinaryRawZIPEntry("safe.jsp", []byte("inert"))})
		binary.LittleEndian.PutUint32(data[:4], 0)
		assertRawZIPError(t, data, "invalid local file header signature")
	})
}

func TestValidateZIPLocalHeadersRejectsAmbiguousEOCD(t *testing.T) {
	data, layout := buildRawZIP(t, []rawZIPEntry{ordinaryRawZIPEntry("safe.jsp", []byte("inert"))})
	fake := append([]byte(nil), data[layout.eocd:layout.eocd+22]...)
	binary.LittleEndian.PutUint16(data[layout.eocd+20:layout.eocd+22], uint16(len(fake)))
	data = append(data, fake...)
	assertRawZIPError(t, data, "ambiguous end of central directory")
}

func TestValidateZIPLocalHeadersBoundsReaderWork(t *testing.T) {
	data, _ := buildRawZIP(t, []rawZIPEntry{ordinaryRawZIPEntry("safe.jsp", []byte("inert"))})
	binary.LittleEndian.PutUint16(data[28:30], ^uint16(0))
	reader := &boundedReaderAt{reader: bytes.NewReader(data), maxRequest: 128 << 10}
	archive, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader() error = %v", err)
	}
	err = ValidateZIPLocalHeaders(reader, int64(len(data)), archive.File)
	if err == nil || !strings.Contains(err.Error(), "truncated local file header name or extra") {
		t.Fatalf("ValidateZIPLocalHeaders() error = %v", err)
	}
	if reader.largest > reader.maxRequest {
		t.Fatalf("largest ReadAt request = %d, want <= %d", reader.largest, reader.maxRequest)
	}
	if reader.total > int64(len(data))*4+128<<10 {
		t.Fatalf("total ReadAt bytes = %d for %d-byte archive", reader.total, len(data))
	}
}

type boundedReaderAt struct {
	reader     io.ReaderAt
	maxRequest int
	largest    int
	total      int64
}

func (reader *boundedReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	if len(buffer) > reader.largest {
		reader.largest = len(buffer)
	}
	reader.total += int64(len(buffer))
	if len(buffer) > reader.maxRequest {
		return 0, io.ErrShortBuffer
	}
	return reader.reader.ReadAt(buffer, offset)
}

func assertLocalZIPError(t *testing.T, entry rawZIPEntry, want string) {
	t.Helper()
	data, _ := buildRawZIP(t, []rawZIPEntry{entry})
	assertRawZIPError(t, data, want)
}

func assertRawZIPError(t *testing.T, data []byte, want string) {
	t.Helper()
	err := validateRawZIP(t, data)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateZIPLocalHeaders() error = %v, want substring %q", err, want)
	}
}

func validateRawZIP(t *testing.T, data []byte) error {
	t.Helper()
	reader := bytes.NewReader(data)
	archive, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader() rejected fixture: %v", err)
	}
	return ValidateZIPLocalHeaders(reader, int64(len(data)), archive.File)
}

func ordinaryRawZIPEntry(name string, data []byte) rawZIPEntry {
	checksum := crc32.ChecksumIEEE(data)
	size := uint32(len(data))
	return rawZIPEntry{
		localName: []byte(name), centralName: []byte(name), data: append([]byte(nil), data...),
		localMethod: zip.Store, centralMethod: zip.Store,
		localCRC: checksum, centralCRC: checksum,
		localCompressed: size, centralCompressed: size,
		localUncompressed: size, centralUncompressed: size,
	}
}

func descriptorRawZIPEntry(name string, data, descriptor []byte) rawZIPEntry {
	entry := ordinaryRawZIPEntry(name, data)
	entry.localFlags = 1 << 3
	entry.centralFlags = 1 << 3
	entry.localCRC = 0
	entry.localCompressed = 0
	entry.localUncompressed = 0
	entry.descriptor = append([]byte(nil), descriptor...)
	return entry
}

func zip64RawZIPEntry(localExtra []byte) rawZIPEntry {
	entry := ordinaryRawZIPEntry("safe.jsp", []byte("inert"))
	entry.localCompressed = ^uint32(0)
	entry.localUncompressed = ^uint32(0)
	entry.centralCompressed = ^uint32(0)
	entry.centralUncompressed = ^uint32(0)
	entry.localExtra = append([]byte(nil), localExtra...)
	entry.centralExtra = zip64LocalExtra(5, 5)
	return entry
}

func descriptor32(signature bool, checksum, compressed, uncompressed uint32) []byte {
	var result []byte
	if signature {
		result = append32(result, testDescriptorSignature)
	}
	result = append32(result, checksum)
	result = append32(result, compressed)
	return append32(result, uncompressed)
}

func descriptor64(signature bool, checksum uint32, compressed, uncompressed uint64) []byte {
	var result []byte
	if signature {
		result = append32(result, testDescriptorSignature)
	}
	result = append32(result, checksum)
	result = append64(result, compressed)
	return append64(result, uncompressed)
}

func zip64LocalExtra(uncompressed, compressed uint64) []byte {
	payload := append64(nil, uncompressed)
	payload = append64(payload, compressed)
	return appendField(nil, testZIP64ExtraID, payload)
}

func appendField(target []byte, tag uint16, payload []byte) []byte {
	target = append16(target, tag)
	target = append16(target, uint16(len(payload)))
	return append(target, payload...)
}

func buildRawZIP(t testing.TB, entries []rawZIPEntry) ([]byte, rawZIPLayout) {
	t.Helper()
	var data []byte
	layout := rawZIPLayout{localOffsets: make([]int, 0, len(entries)), dataOffsets: make([]int, 0, len(entries))}
	actualOffsets := make([]uint32, 0, len(entries))
	for _, entry := range entries {
		if len(entry.localName) > int(^uint16(0)) || len(entry.localExtra) > int(^uint16(0)) {
			t.Fatal("local fixture field too long")
		}
		actualOffsets = append(actualOffsets, uint32(len(data)))
		layout.localOffsets = append(layout.localOffsets, len(data))
		data = append32(data, testLocalHeaderSignature)
		data = append16(data, 20)
		data = append16(data, entry.localFlags)
		data = append16(data, entry.localMethod)
		data = append16(data, 0)
		data = append16(data, 0)
		data = append32(data, entry.localCRC)
		data = append32(data, entry.localCompressed)
		data = append32(data, entry.localUncompressed)
		data = append16(data, uint16(len(entry.localName)))
		data = append16(data, uint16(len(entry.localExtra)))
		data = append(data, entry.localName...)
		data = append(data, entry.localExtra...)
		layout.dataOffsets = append(layout.dataOffsets, len(data))
		data = append(data, entry.data...)
		data = append(data, entry.descriptor...)
	}

	layout.central = len(data)
	for index, entry := range entries {
		if len(entry.centralName) > int(^uint16(0)) || len(entry.centralExtra) > int(^uint16(0)) {
			t.Fatal("central fixture field too long")
		}
		data = append32(data, testCentralSignature)
		data = append16(data, 20)
		data = append16(data, 20)
		data = append16(data, entry.centralFlags)
		data = append16(data, entry.centralMethod)
		data = append16(data, 0)
		data = append16(data, 0)
		data = append32(data, entry.centralCRC)
		data = append32(data, entry.centralCompressed)
		data = append32(data, entry.centralUncompressed)
		data = append16(data, uint16(len(entry.centralName)))
		data = append16(data, uint16(len(entry.centralExtra)))
		data = append16(data, 0)
		data = append16(data, 0)
		data = append16(data, 0)
		data = append32(data, 0)
		offset := actualOffsets[index]
		if entry.localOffsetOverride != nil {
			offset = *entry.localOffsetOverride
		}
		data = append32(data, offset)
		data = append(data, entry.centralName...)
		data = append(data, entry.centralExtra...)
	}

	layout.eocd = len(data)
	centralSize := len(data) - layout.central
	data = append32(data, testEOCDSignature)
	data = append16(data, 0)
	data = append16(data, 0)
	data = append16(data, uint16(len(entries)))
	data = append16(data, uint16(len(entries)))
	data = append32(data, uint32(centralSize))
	data = append32(data, uint32(layout.central))
	data = append16(data, 0)
	return data, layout
}

func overlappingRawZIP(t testing.TB) []byte {
	t.Helper()
	second := ordinaryRawZIPEntry("two.jsp", []byte("two"))
	secondBytes, secondLayout := buildRawZIP(t, []rawZIPEntry{second})
	secondLocal := append([]byte(nil), secondBytes[:secondLayout.central]...)

	firstData := append([]byte("pad!"), secondLocal...)
	first := ordinaryRawZIPEntry("one.jsp", firstData)
	firstOnly, firstLayout := buildRawZIP(t, []rawZIPEntry{first})
	firstLocalAndData := append([]byte(nil), firstOnly[:firstLayout.central]...)
	secondOffset := uint32(firstLayout.dataOffsets[0] + len("pad!"))

	entries := []rawZIPEntry{first, second}
	var data []byte
	data = append(data, firstLocalAndData...)
	centralStart := len(data)
	for index, entry := range entries {
		data = append32(data, testCentralSignature)
		data = append16(data, 20)
		data = append16(data, 20)
		data = append16(data, entry.centralFlags)
		data = append16(data, entry.centralMethod)
		data = append16(data, 0)
		data = append16(data, 0)
		data = append32(data, entry.centralCRC)
		data = append32(data, entry.centralCompressed)
		data = append32(data, entry.centralUncompressed)
		data = append16(data, uint16(len(entry.centralName)))
		data = append16(data, 0)
		data = append16(data, 0)
		data = append16(data, 0)
		data = append16(data, 0)
		data = append32(data, 0)
		if index == 0 {
			data = append32(data, 0)
		} else {
			data = append32(data, secondOffset)
		}
		data = append(data, entry.centralName...)
	}
	centralSize := len(data) - centralStart
	data = append32(data, testEOCDSignature)
	data = append16(data, 0)
	data = append16(data, 0)
	data = append16(data, 2)
	data = append16(data, 2)
	data = append32(data, uint32(centralSize))
	data = append32(data, uint32(centralStart))
	return append16(data, 0)
}

func append16(target []byte, value uint16) []byte {
	var buffer [2]byte
	binary.LittleEndian.PutUint16(buffer[:], value)
	return append(target, buffer[:]...)
}

func append32(target []byte, value uint32) []byte {
	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], value)
	return append(target, buffer[:]...)
}

func append64(target []byte, value uint64) []byte {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	return append(target, buffer[:]...)
}
