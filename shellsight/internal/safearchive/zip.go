package safearchive

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
)

var ErrCompressedEntryLimit = errors.New("compressed entry byte limit exceeded")

type ZIPEntry struct {
	File         *zip.File
	Name         string
	OriginalName string
	Priority     int
	Err          error
}

type ZIPLimits struct {
	MaxCompressedBytes int64
	MaxExpandedBytes   int64
	MaxTotalBytes      int64
	MaxRatio           int64
	RatioFloor         int64
}

type archiveError struct {
	budget bool
	detail string
}

func (err *archiveError) Error() string { return err.detail }

func IsBudgetError(err error) bool {
	var target *archiveError
	return errors.As(err, &target) && target.budget
}

func budgetError(detail string) error {
	return &archiveError{budget: true, detail: detail}
}

func formatError(format string, args ...any) error {
	return &archiveError{detail: fmt.Sprintf(format, args...)}
}

const (
	zipLocalHeaderSignature    = 0x04034b50
	zipCentralHeaderSignature  = 0x02014b50
	zipEOCDSignature           = 0x06054b50
	zip64EOCDSignature         = 0x06064b50
	zip64LocatorSignature      = 0x07064b50
	zipDataDescriptorSignature = 0x08074b50
	zip64ExtraID               = 0x0001

	zipLocalHeaderLen   = 30
	zipCentralHeaderLen = 46
	zipEOCDLen          = 22
	zip64EOCDLen        = 56
	zip64LocatorLen     = 20
	zipMaxEOCDSearch    = zipEOCDLen + 1<<16 - 1
)

type zipCentralRecord struct {
	localOffset       int64
	compressedZIP64   bool
	uncompressedZIP64 bool
}

type zipCentralDirectory struct {
	start   int64
	records []zipCentralRecord
}

type zipLocalSpan struct {
	file         *zip.File
	record       zipCentralRecord
	start        int64
	dataStart    int64
	dataEnd      int64
	end          int64
	descriptor   bool
	descriptor64 bool
}

// ValidateZIPLocalHeaders verifies the raw local records corresponding to
// files before a caller opens entry content. It parses the EOCD and central
// directory to recover local offsets, then requires archive/zip's DataOffset
// view to agree with the raw records. Work is linear in the bounded ZIP
// metadata and each variable field is capped by its 16-bit on-disk length.
func ValidateZIPLocalHeaders(reader io.ReaderAt, size int64, files []*zip.File) error {
	if reader == nil {
		return errors.New("validate ZIP local headers: nil reader")
	}
	if size < 0 {
		return fmt.Errorf("validate ZIP local headers: invalid size %d", size)
	}
	if int64(len(files)) > size/zipCentralHeaderLen+1 {
		return errors.New("validate ZIP local headers: impossible file count")
	}
	directory, err := parseZIPCentralDirectory(reader, size, files)
	if err != nil {
		return fmt.Errorf("validate ZIP local headers: %w", err)
	}
	spans := make([]zipLocalSpan, 0, len(files))
	seenOffsets := make(map[int64]struct{}, len(files))
	for index, file := range files {
		if file == nil {
			return fmt.Errorf("validate ZIP local headers: nil file at central index %d", index)
		}
		record := directory.records[index]
		if _, duplicate := seenOffsets[record.localOffset]; duplicate {
			return fmt.Errorf("duplicate local header offset %d", record.localOffset)
		}
		seenOffsets[record.localOffset] = struct{}{}
		span, err := parseZIPLocalSpan(reader, size, directory.start, record, file)
		if err != nil {
			return fmt.Errorf("ZIP local header for %q: %w", file.Name, err)
		}
		spans = append(spans, span)
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for index := range spans {
		boundary := directory.start
		if index+1 < len(spans) {
			boundary = spans[index+1].start
		}
		span := &spans[index]
		if span.dataEnd > boundary {
			return fmt.Errorf("overlapping ZIP entry spans at local offset %d", span.start)
		}
		if span.descriptor {
			end, err := validateZIPDataDescriptor(reader, size, span.dataEnd, boundary, span.file, span.descriptor64)
			if err != nil {
				return fmt.Errorf("ZIP data descriptor for %q: %w", span.file.Name, err)
			}
			span.end = end
		} else {
			matches, err := matchingZIPDataDescriptor(reader, size, span.dataEnd, boundary, span.file, span.descriptor64)
			if err != nil {
				return fmt.Errorf("inspect data after %q: %w", span.file.Name, err)
			}
			if matches {
				return fmt.Errorf("unexpected data descriptor for %q without general-purpose bit 3", span.file.Name)
			}
		}
		if span.end > boundary {
			return fmt.Errorf("overlapping ZIP entry spans at local offset %d", span.start)
		}
	}
	return nil
}

func parseZIPCentralDirectory(reader io.ReaderAt, size int64, files []*zip.File) (zipCentralDirectory, error) {
	eocdOffset, eocd, err := findUniqueZIPEOCD(reader, size)
	if err != nil {
		return zipCentralDirectory{}, err
	}
	if binary.LittleEndian.Uint16(eocd[4:6]) != 0 || binary.LittleEndian.Uint16(eocd[6:8]) != 0 {
		return zipCentralDirectory{}, errors.New("multi-disk ZIP archive rejected")
	}
	recordsDisk := uint64(binary.LittleEndian.Uint16(eocd[8:10]))
	records := uint64(binary.LittleEndian.Uint16(eocd[10:12]))
	directorySize := uint64(binary.LittleEndian.Uint32(eocd[12:16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(eocd[16:20]))
	if recordsDisk != records {
		return zipCentralDirectory{}, errors.New("inconsistent central directory record counts")
	}
	centralEnd := eocdOffset
	if records == 0xffff || directorySize == uint64(^uint32(0)) || directoryOffset == uint64(^uint32(0)) {
		records, directorySize, directoryOffset, centralEnd, err = parseZIP64DirectoryEnd(reader, size, eocdOffset)
		if err != nil {
			return zipCentralDirectory{}, err
		}
	}
	if records != uint64(len(files)) {
		return zipCentralDirectory{}, fmt.Errorf("central directory contains %d records but archive/zip returned %d files", records, len(files))
	}
	if directorySize > uint64(centralEnd) || directoryOffset > uint64(centralEnd) {
		return zipCentralDirectory{}, errors.New("central directory offset or size out of range")
	}
	centralStart := centralEnd - int64(directorySize)
	baseOffset := centralStart - int64(directoryOffset)
	if centralStart < 0 || baseOffset < 0 {
		return zipCentralDirectory{}, errors.New("invalid central directory base offset")
	}
	parsed, err := parseZIPCentralRecords(reader, size, centralStart, centralEnd, records, files, baseOffset)
	if err != nil {
		return zipCentralDirectory{}, err
	}
	return zipCentralDirectory{start: centralStart, records: parsed}, nil
}

func findUniqueZIPEOCD(reader io.ReaderAt, size int64) (int64, []byte, error) {
	if size < zipEOCDLen {
		return 0, nil, errors.New("truncated end of central directory")
	}
	searchLength := size
	if searchLength > zipMaxEOCDSearch {
		searchLength = zipMaxEOCDSearch
	}
	buffer, err := readZIPBytes(reader, size, size-searchLength, searchLength)
	if err != nil {
		return 0, nil, fmt.Errorf("read end of central directory search window: %w", err)
	}
	var matches []int
	for index := len(buffer) - zipEOCDLen; index >= 0; index-- {
		if binary.LittleEndian.Uint32(buffer[index:index+4]) != zipEOCDSignature {
			continue
		}
		commentLength := int(binary.LittleEndian.Uint16(buffer[index+20 : index+22]))
		if index+zipEOCDLen+commentLength == len(buffer) {
			matches = append(matches, index)
		}
	}
	if len(matches) == 0 {
		return 0, nil, errors.New("end of central directory not found")
	}
	if len(matches) != 1 {
		return 0, nil, errors.New("ambiguous end of central directory records")
	}
	index := matches[0]
	return size - searchLength + int64(index), buffer[index : index+zipEOCDLen], nil
}

func parseZIP64DirectoryEnd(reader io.ReaderAt, size, eocdOffset int64) (uint64, uint64, uint64, int64, error) {
	locatorOffset := eocdOffset - zip64LocatorLen
	if locatorOffset < 0 {
		return 0, 0, 0, 0, errors.New("missing ZIP64 end locator")
	}
	locator, err := readZIPBytes(reader, size, locatorOffset, zip64LocatorLen)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read ZIP64 end locator: %w", err)
	}
	if binary.LittleEndian.Uint32(locator[:4]) != zip64LocatorSignature {
		return 0, 0, 0, 0, errors.New("missing ZIP64 end locator")
	}
	if binary.LittleEndian.Uint32(locator[4:8]) != 0 || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		return 0, 0, 0, 0, errors.New("multi-disk ZIP64 archive rejected")
	}
	zip64Offset64 := binary.LittleEndian.Uint64(locator[8:16])
	if zip64Offset64 > uint64(^uint64(0)>>1) {
		return 0, 0, 0, 0, errors.New("ZIP64 end offset out of range")
	}
	zip64Offset := int64(zip64Offset64)
	header, err := readZIPBytes(reader, size, zip64Offset, zip64EOCDLen)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read ZIP64 end record: %w", err)
	}
	if binary.LittleEndian.Uint32(header[:4]) != zip64EOCDSignature {
		return 0, 0, 0, 0, errors.New("invalid ZIP64 end record signature")
	}
	recordSize := binary.LittleEndian.Uint64(header[4:12])
	if recordSize < zip64EOCDLen-12 || recordSize > uint64(^uint64(0)>>1)-12 {
		return 0, 0, 0, 0, errors.New("invalid ZIP64 end record size")
	}
	if zip64Offset > locatorOffset-int64(recordSize+12) || zip64Offset+int64(recordSize+12) != locatorOffset {
		return 0, 0, 0, 0, errors.New("truncated or ambiguous ZIP64 end record")
	}
	if binary.LittleEndian.Uint32(header[16:20]) != 0 || binary.LittleEndian.Uint32(header[20:24]) != 0 {
		return 0, 0, 0, 0, errors.New("multi-disk ZIP64 archive rejected")
	}
	recordsDisk := binary.LittleEndian.Uint64(header[24:32])
	records := binary.LittleEndian.Uint64(header[32:40])
	if recordsDisk != records {
		return 0, 0, 0, 0, errors.New("inconsistent ZIP64 central directory record counts")
	}
	return records, binary.LittleEndian.Uint64(header[40:48]), binary.LittleEndian.Uint64(header[48:56]), zip64Offset, nil
}

func parseZIPCentralRecords(
	reader io.ReaderAt,
	size, start, end int64,
	recordCount uint64,
	files []*zip.File,
	baseOffset int64,
) ([]zipCentralRecord, error) {
	if recordCount != 0 && uint64(end-start)/zipCentralHeaderLen < recordCount {
		return nil, errors.New("central directory record count exceeds bounded directory size")
	}
	records := make([]zipCentralRecord, 0, len(files))
	offset := start
	for index, file := range files {
		if offset > end-zipCentralHeaderLen {
			return nil, errors.New("truncated central directory header")
		}
		header, err := readZIPBytes(reader, size, offset, zipCentralHeaderLen)
		if err != nil {
			return nil, fmt.Errorf("read central directory header %d: %w", index, err)
		}
		if binary.LittleEndian.Uint32(header[:4]) != zipCentralHeaderSignature {
			return nil, fmt.Errorf("invalid central directory signature at record %d", index)
		}
		nameLength := int64(binary.LittleEndian.Uint16(header[28:30]))
		extraLength := int64(binary.LittleEndian.Uint16(header[30:32]))
		commentLength := int64(binary.LittleEndian.Uint16(header[32:34]))
		recordLength := int64(zipCentralHeaderLen) + nameLength + extraLength + commentLength
		if recordLength > end-offset {
			return nil, fmt.Errorf("truncated central directory variable fields at record %d", index)
		}
		name, err := readZIPBytes(reader, size, offset+zipCentralHeaderLen, nameLength)
		if err != nil {
			return nil, fmt.Errorf("read central directory name %d: %w", index, err)
		}
		extra, err := readZIPBytes(reader, size, offset+zipCentralHeaderLen+nameLength, extraLength)
		if err != nil {
			return nil, fmt.Errorf("read central directory extra %d: %w", index, err)
		}
		if file == nil {
			return nil, fmt.Errorf("nil archive/zip file at central index %d", index)
		}
		if string(name) != file.Name {
			return nil, fmt.Errorf("central name mismatch at record %d", index)
		}
		flags := binary.LittleEndian.Uint16(header[8:10])
		method := binary.LittleEndian.Uint16(header[10:12])
		checksum := binary.LittleEndian.Uint32(header[16:20])
		if flags != file.Flags || method != file.Method || checksum != file.CRC32 {
			return nil, fmt.Errorf("central metadata disagrees with archive/zip at record %d", index)
		}
		if binary.LittleEndian.Uint16(header[34:36]) != 0 {
			return nil, errors.New("multi-disk central directory entry rejected")
		}
		compressed32 := binary.LittleEndian.Uint32(header[20:24])
		uncompressed32 := binary.LittleEndian.Uint32(header[24:28])
		localOffset32 := binary.LittleEndian.Uint32(header[42:46])
		compressedZIP64 := compressed32 == ^uint32(0)
		uncompressedZIP64 := uncompressed32 == ^uint32(0)
		offsetZIP64 := localOffset32 == ^uint32(0)
		compressed := uint64(compressed32)
		uncompressed := uint64(uncompressed32)
		localOffset := uint64(localOffset32)
		if compressedZIP64 || uncompressedZIP64 || offsetZIP64 {
			compressed, uncompressed, localOffset, err = parseCentralZIP64Extra(
				extra, compressedZIP64, uncompressedZIP64, offsetZIP64,
				compressed, uncompressed, localOffset,
			)
			if err != nil {
				return nil, fmt.Errorf("central ZIP64 extra for %q: %w", file.Name, err)
			}
		}
		if compressed != file.CompressedSize64 || uncompressed != file.UncompressedSize64 {
			return nil, fmt.Errorf("central sizes disagree with archive/zip for %q", file.Name)
		}
		if localOffset > uint64(^uint64(0)>>1) || localOffset > uint64(^uint64(0)>>1)-uint64(baseOffset) {
			return nil, fmt.Errorf("local header offset out of range for %q", file.Name)
		}
		records = append(records, zipCentralRecord{
			localOffset:       int64(localOffset) + baseOffset,
			compressedZIP64:   compressedZIP64,
			uncompressedZIP64: uncompressedZIP64,
		})
		offset += recordLength
	}
	if offset != end {
		return nil, errors.New("central directory size does not exactly match its records")
	}
	return records, nil
}

func parseCentralZIP64Extra(
	extra []byte,
	needCompressed, needUncompressed, needOffset bool,
	compressed, uncompressed, offset uint64,
) (uint64, uint64, uint64, error) {
	field, found, err := findUniqueZIP64Extra(extra, "central")
	if err != nil {
		return 0, 0, 0, err
	}
	if !found {
		return 0, 0, 0, errors.New("missing central ZIP64 extra")
	}
	readValue := func(name string) (uint64, error) {
		if len(field) < 8 {
			return 0, fmt.Errorf("truncated central ZIP64 %s", name)
		}
		value := binary.LittleEndian.Uint64(field[:8])
		field = field[8:]
		return value, nil
	}
	if needUncompressed {
		uncompressed, err = readValue("uncompressed size")
		if err != nil {
			return 0, 0, 0, err
		}
	}
	if needCompressed {
		compressed, err = readValue("compressed size")
		if err != nil {
			return 0, 0, 0, err
		}
	}
	if needOffset {
		offset, err = readValue("local header offset")
		if err != nil {
			return 0, 0, 0, err
		}
	}
	return compressed, uncompressed, offset, nil
}

func parseZIPLocalSpan(
	reader io.ReaderAt,
	size, centralStart int64,
	record zipCentralRecord,
	file *zip.File,
) (zipLocalSpan, error) {
	if record.localOffset < 0 || record.localOffset >= centralStart {
		return zipLocalSpan{}, fmt.Errorf("local header offset out of range: %d", record.localOffset)
	}
	if record.localOffset > centralStart-zipLocalHeaderLen {
		return zipLocalSpan{}, errors.New("truncated local file header")
	}
	header, err := readZIPBytes(reader, size, record.localOffset, zipLocalHeaderLen)
	if err != nil {
		return zipLocalSpan{}, fmt.Errorf("read local file header: %w", err)
	}
	if binary.LittleEndian.Uint32(header[:4]) != zipLocalHeaderSignature {
		return zipLocalSpan{}, errors.New("invalid local file header signature")
	}
	nameLength := int64(binary.LittleEndian.Uint16(header[26:28]))
	extraLength := int64(binary.LittleEndian.Uint16(header[28:30]))
	headerEnd := record.localOffset + zipLocalHeaderLen + nameLength + extraLength
	if headerEnd < record.localOffset || headerEnd > centralStart {
		return zipLocalSpan{}, errors.New("truncated local file header name or extra")
	}
	name, err := readZIPBytes(reader, size, record.localOffset+zipLocalHeaderLen, nameLength)
	if err != nil {
		return zipLocalSpan{}, fmt.Errorf("read local file name: %w", err)
	}
	extra, err := readZIPBytes(reader, size, record.localOffset+zipLocalHeaderLen+nameLength, extraLength)
	if err != nil {
		return zipLocalSpan{}, fmt.Errorf("read local file extra: %w", err)
	}
	localName := string(name)
	if strings.Contains(localName, `\`) {
		return zipLocalSpan{}, fmt.Errorf("unsafe local ZIP entry name %q", localName)
	}
	localNormalized, err := NormalizePath(localName)
	if err != nil {
		return zipLocalSpan{}, fmt.Errorf("unsafe local ZIP entry name %q: %w", localName, err)
	}
	centralNormalized, err := NormalizePath(file.Name)
	if err != nil {
		return zipLocalSpan{}, fmt.Errorf("unsafe central ZIP entry name %q: %w", file.Name, err)
	}
	if localName != file.Name {
		return zipLocalSpan{}, fmt.Errorf("local and central name mismatch: %q != %q", localName, file.Name)
	}
	if localNormalized != centralNormalized {
		return zipLocalSpan{}, fmt.Errorf("local and central normalized path mismatch: %q != %q", localNormalized, centralNormalized)
	}
	flags := binary.LittleEndian.Uint16(header[6:8])
	if flags&(1|1<<6) != 0 || file.Flags&(1|1<<6) != 0 {
		return zipLocalSpan{}, errors.New("encrypted ZIP entry rejected")
	}
	if flags != file.Flags {
		return zipLocalSpan{}, fmt.Errorf("local and central flags mismatch: %#x != %#x", flags, file.Flags)
	}
	method := binary.LittleEndian.Uint16(header[8:10])
	if method != zip.Store && method != zip.Deflate {
		return zipLocalSpan{}, fmt.Errorf("unsupported ZIP compression method %d", method)
	}
	if file.Method != zip.Store && file.Method != zip.Deflate {
		return zipLocalSpan{}, fmt.Errorf("unsupported ZIP compression method %d", file.Method)
	}
	if method != file.Method {
		return zipLocalSpan{}, fmt.Errorf("local and central method mismatch: %d != %d", method, file.Method)
	}
	localCRC := binary.LittleEndian.Uint32(header[14:18])
	localCompressed := binary.LittleEndian.Uint32(header[18:22])
	localUncompressed := binary.LittleEndian.Uint32(header[22:26])
	descriptor := flags&(1<<3) != 0
	if descriptor {
		if localCRC != 0 {
			return zipLocalSpan{}, errors.New("data-descriptor local CRC must be zero")
		}
		switch {
		case localCompressed == 0 && localUncompressed == 0:
			if err := validateLocalZIP64Extra(extra, false, false, file); err != nil {
				return zipLocalSpan{}, err
			}
		case localCompressed == ^uint32(0) && localUncompressed == ^uint32(0):
			if err := validateLocalZIP64Extra(extra, true, true, file); err != nil {
				return zipLocalSpan{}, err
			}
		default:
			return zipLocalSpan{}, errors.New("data-descriptor local sizes must both be zero or ZIP64 sentinels")
		}
	} else {
		if localCRC != file.CRC32 {
			return zipLocalSpan{}, errors.New("local and central CRC mismatch")
		}
		needCompressed := localCompressed == ^uint32(0)
		needUncompressed := localUncompressed == ^uint32(0)
		if err := validateLocalZIP64Extra(extra, needCompressed, needUncompressed, file); err != nil {
			return zipLocalSpan{}, err
		}
		if !needCompressed && uint64(localCompressed) != file.CompressedSize64 {
			return zipLocalSpan{}, errors.New("local and central compressed size mismatch")
		}
		if !needUncompressed && uint64(localUncompressed) != file.UncompressedSize64 {
			return zipLocalSpan{}, errors.New("local and central uncompressed size mismatch")
		}
	}
	dataOffset, err := file.DataOffset()
	if err != nil {
		return zipLocalSpan{}, fmt.Errorf("archive/zip DataOffset: %w", err)
	}
	if dataOffset != headerEnd {
		return zipLocalSpan{}, fmt.Errorf("ambiguous local data offset: raw=%d archive/zip=%d", headerEnd, dataOffset)
	}
	if file.CompressedSize64 > uint64(centralStart) || dataOffset > centralStart-int64(file.CompressedSize64) {
		return zipLocalSpan{}, errors.New("compressed data range out of bounds")
	}
	dataEnd := dataOffset + int64(file.CompressedSize64)
	return zipLocalSpan{
		file: file, record: record, start: record.localOffset,
		dataStart: dataOffset, dataEnd: dataEnd, end: dataEnd,
		descriptor: descriptor, descriptor64: record.compressedZIP64 || record.uncompressedZIP64,
	}, nil
}

func validateLocalZIP64Extra(extra []byte, needCompressed, needUncompressed bool, file *zip.File) error {
	field, found, err := findUniqueZIP64Extra(extra, "local")
	if err != nil {
		return err
	}
	if !needCompressed && !needUncompressed {
		if found {
			return errors.New("unnecessary local ZIP64 extra without size sentinels")
		}
		return nil
	}
	if !found {
		return errors.New("missing local ZIP64 extra for size sentinel")
	}
	required := 0
	if needUncompressed {
		required += 8
	}
	if needCompressed {
		required += 8
	}
	if len(field) < required {
		return errors.New("truncated local ZIP64 size extra")
	}
	if len(field) > required {
		return errors.New("ambiguous local ZIP64 extra contains unnecessary values")
	}
	offset := 0
	if needUncompressed {
		value := binary.LittleEndian.Uint64(field[offset : offset+8])
		if value != file.UncompressedSize64 {
			return errors.New("local ZIP64 uncompressed size mismatch")
		}
		offset += 8
	}
	if needCompressed {
		value := binary.LittleEndian.Uint64(field[offset : offset+8])
		if value != file.CompressedSize64 {
			return errors.New("local ZIP64 compressed size mismatch")
		}
	}
	return nil
}

func findUniqueZIP64Extra(extra []byte, location string) ([]byte, bool, error) {
	var found []byte
	for len(extra) != 0 {
		if len(extra) < 4 {
			return nil, false, fmt.Errorf("truncated %s extra field header", location)
		}
		tag := binary.LittleEndian.Uint16(extra[:2])
		length := int(binary.LittleEndian.Uint16(extra[2:4]))
		extra = extra[4:]
		if length > len(extra) {
			if tag == zip64ExtraID {
				return nil, false, fmt.Errorf("truncated %s ZIP64 extra", location)
			}
			return nil, false, fmt.Errorf("truncated %s extra field", location)
		}
		field := extra[:length]
		extra = extra[length:]
		if tag != zip64ExtraID {
			continue
		}
		if found != nil {
			return nil, false, fmt.Errorf("duplicate %s ZIP64 extra", location)
		}
		found = field
	}
	return found, found != nil, nil
}

func validateZIPDataDescriptor(
	reader io.ReaderAt,
	size, offset, boundary int64,
	file *zip.File,
	zip64 bool,
) (int64, error) {
	if boundary-offset < 4 {
		return 0, errors.New("truncated data descriptor")
	}
	first, err := readZIPBytes(reader, size, offset, 4)
	if err != nil {
		return 0, fmt.Errorf("read data descriptor prefix: %w", err)
	}
	firstValue := binary.LittleEndian.Uint32(first)
	signed := firstValue == zipDataDescriptorSignature
	if signed && file.CRC32 == zipDataDescriptorSignature {
		return 0, errors.New("ambiguous data descriptor signature because CRC equals the optional signature")
	}
	width := int64(4)
	if zip64 {
		width = 8
	}
	descriptorLength := int64(4) + width*2
	payloadOffset := offset
	if signed {
		descriptorLength += 4
		payloadOffset += 4
	}
	if descriptorLength > boundary-offset {
		return 0, errors.New("truncated data descriptor")
	}
	payload, err := readZIPBytes(reader, size, payloadOffset, descriptorLength-(payloadOffset-offset))
	if err != nil {
		return 0, fmt.Errorf("read data descriptor: %w", err)
	}
	if binary.LittleEndian.Uint32(payload[:4]) != file.CRC32 {
		return 0, errors.New("data descriptor CRC mismatch")
	}
	if zip64 {
		if binary.LittleEndian.Uint64(payload[4:12]) != file.CompressedSize64 {
			return 0, errors.New("data descriptor compressed size mismatch")
		}
		if binary.LittleEndian.Uint64(payload[12:20]) != file.UncompressedSize64 {
			return 0, errors.New("data descriptor uncompressed size mismatch")
		}
	} else {
		if binary.LittleEndian.Uint32(payload[4:8]) != uint32(file.CompressedSize64) {
			return 0, errors.New("data descriptor compressed size mismatch")
		}
		if binary.LittleEndian.Uint32(payload[8:12]) != uint32(file.UncompressedSize64) {
			return 0, errors.New("data descriptor uncompressed size mismatch")
		}
	}
	return offset + descriptorLength, nil
}

func matchingZIPDataDescriptor(
	reader io.ReaderAt,
	size, offset, boundary int64,
	file *zip.File,
	zip64 bool,
) (bool, error) {
	if boundary-offset < 4 {
		return false, nil
	}
	first, err := readZIPBytes(reader, size, offset, 4)
	if err != nil {
		return false, err
	}
	firstValue := binary.LittleEndian.Uint32(first)
	lengths := []int64{12}
	if zip64 {
		lengths = []int64{20}
	}
	if firstValue == zipDataDescriptorSignature {
		lengths = append(lengths, lengths[0]+4)
	}
	for _, length := range lengths {
		if length > boundary-offset {
			continue
		}
		buffer, err := readZIPBytes(reader, size, offset, length)
		if err != nil {
			return false, err
		}
		payload := buffer
		if length%8 == 0 {
			if binary.LittleEndian.Uint32(buffer[:4]) != zipDataDescriptorSignature {
				continue
			}
			payload = buffer[4:]
		}
		if binary.LittleEndian.Uint32(payload[:4]) != file.CRC32 {
			continue
		}
		if zip64 {
			if binary.LittleEndian.Uint64(payload[4:12]) == file.CompressedSize64 &&
				binary.LittleEndian.Uint64(payload[12:20]) == file.UncompressedSize64 {
				return true, nil
			}
		} else if binary.LittleEndian.Uint32(payload[4:8]) == uint32(file.CompressedSize64) &&
			binary.LittleEndian.Uint32(payload[8:12]) == uint32(file.UncompressedSize64) {
			return true, nil
		}
	}
	return false, nil
}

func readZIPBytes(reader io.ReaderAt, size, offset, length int64) ([]byte, error) {
	if offset < 0 || length < 0 || offset > size || length > size-offset {
		return nil, io.ErrUnexpectedEOF
	}
	if length > int64(^uint(0)>>1) {
		return nil, errors.New("ZIP metadata allocation exceeds platform int")
	}
	buffer := make([]byte, int(length))
	if length == 0 {
		return buffer, nil
	}
	n, err := reader.ReadAt(buffer, offset)
	if n != len(buffer) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buffer, nil
}

// PrepareZIP validates and sorts ZIP metadata. Colliding normalized names are
// represented by one error entry and neither colliding member is returned.
func PrepareZIP(files []*zip.File, priority func(string) int) []ZIPEntry {
	if priority == nil {
		priority = func(string) int { return 0 }
	}
	valid := make([]ZIPEntry, 0, len(files))
	invalid := make([]ZIPEntry, 0)
	counts := make(map[string]int, len(files))
	for _, file := range files {
		name, err := NormalizePath(file.Name)
		if err != nil {
			invalid = append(invalid, ZIPEntry{File: file, OriginalName: file.Name, Err: err})
			continue
		}
		valid = append(valid, ZIPEntry{
			File: file, Name: name, OriginalName: file.Name, Priority: priority(name),
		})
		counts[name]++
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Priority != valid[j].Priority {
			return valid[i].Priority < valid[j].Priority
		}
		if valid[i].Name != valid[j].Name {
			return valid[i].Name < valid[j].Name
		}
		return valid[i].OriginalName < valid[j].OriginalName
	})
	sort.Slice(invalid, func(i, j int) bool {
		left := strings.ReplaceAll(invalid[i].OriginalName, `\`, "/")
		right := strings.ReplaceAll(invalid[j].OriginalName, `\`, "/")
		if left != right {
			return left < right
		}
		return invalid[i].OriginalName < invalid[j].OriginalName
	})

	entries := append([]ZIPEntry(nil), invalid...)
	reported := make(map[string]struct{})
	for _, entry := range valid {
		if counts[entry.Name] > 1 {
			if _, ok := reported[entry.Name]; !ok {
				entries = append(entries, ZIPEntry{
					Name: entry.Name, OriginalName: entry.OriginalName, Priority: entry.Priority,
					Err: errors.New("duplicate normalized archive entry path rejected"),
				})
				reported[entry.Name] = struct{}{}
			}
			continue
		}
		if entry.File.Flags&1 != 0 {
			entry.Err = errors.New("encrypted archive entry rejected")
			entries = append(entries, entry)
			continue
		}
		if entry.File.Method != zip.Store && entry.File.Method != zip.Deflate {
			entry.Err = fmt.Errorf("unsupported ZIP compression method %d", entry.File.Method)
		}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Priority != entries[j].Priority {
			return entries[i].Priority < entries[j].Priority
		}
		left, right := entries[i].Name, entries[j].Name
		if left == "" {
			left = strings.ReplaceAll(entries[i].OriginalName, `\`, "/")
		}
		if right == "" {
			right = strings.ReplaceAll(entries[j].OriginalName, `\`, "/")
		}
		if left != right {
			return left < right
		}
		return entries[i].OriginalName < entries[j].OriginalName
	})
	return entries
}

type CompressedCounter struct {
	reader io.Reader
	read   int64
	max    int64
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := reader.reader.Read(buffer)
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

func NewCompressedCounter(reader io.Reader, max int64) *CompressedCounter {
	return &CompressedCounter{reader: reader, max: max}
}

func (reader *CompressedCounter) BytesRead() int64 { return reader.read }

func (reader *CompressedCounter) Read(buffer []byte) (int, error) {
	if reader.max < 0 || reader.read > reader.max {
		return 0, ErrCompressedEntryLimit
	}
	remaining := reader.max - reader.read
	if int64(len(buffer)) > remaining {
		buffer = buffer[:remaining+1]
	}
	n, err := reader.reader.Read(buffer)
	if int64(n) > remaining {
		const maxInt64 = int64(^uint64(0) >> 1)
		if reader.max < maxInt64 {
			reader.read = reader.max + 1
		} else {
			reader.read = maxInt64
		}
		return n, ErrCompressedEntryLimit
	}
	reader.read += int64(n)
	return n, err
}

func CompressionRatioExceeded(expanded, compressed, floor, maximum int64) bool {
	if compressed < floor || compressed <= 0 {
		return false
	}
	return expanded/compressed > maximum ||
		expanded/compressed == maximum && expanded%compressed != 0
}

func ReadZIPEntry(ctx context.Context, file *zip.File, limits ZIPLimits, total *int64) (result []byte, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if file.Flags&1 != 0 {
		return nil, formatError("encrypted archive entry rejected")
	}
	if file.Method != zip.Store && file.Method != zip.Deflate {
		return nil, formatError("unsupported ZIP compression method %d", file.Method)
	}
	if file.UncompressedSize64 > uint64(limits.MaxExpandedBytes) {
		return nil, budgetError("entry expanded byte limit reached")
	}
	if file.CompressedSize64 > uint64(limits.MaxCompressedBytes) {
		return nil, budgetError("entry compressed byte limit reached")
	}
	raw, err := file.OpenRaw()
	if err != nil {
		return nil, formatError("open archive entry: %v", err)
	}
	counter := NewCompressedCounter(&contextReader{ctx: ctx, reader: raw}, limits.MaxCompressedBytes)
	var expanded io.Reader = counter
	var inflater io.ReadCloser
	if file.Method == zip.Deflate {
		inflater = flate.NewReader(counter)
		expanded = inflater
		defer func() {
			if closeErr := inflater.Close(); closeErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("close archive entry inflater: %w", closeErr))
			}
		}()
	}

	if total == nil {
		total = new(int64)
	}
	var output bytes.Buffer
	checksum := crc32.NewIEEE()
	buffer := make([]byte, 32<<10)
	entryExpanded := int64(0)
	for {
		n, readErr := expanded.Read(buffer)
		if n != 0 {
			entryExpanded += int64(n)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if entryExpanded > limits.MaxExpandedBytes {
				return nil, budgetError("entry expanded byte limit reached")
			}
			if int64(n) > limits.MaxTotalBytes || *total > limits.MaxTotalBytes-int64(n) {
				return nil, budgetError("archive expanded byte limit reached")
			}
			*total += int64(n)
			_, _ = checksum.Write(buffer[:n])
			_, _ = output.Write(buffer[:n])
			if CompressionRatioExceeded(entryExpanded, counter.BytesRead(), limits.RatioFloor, limits.MaxRatio) {
				return nil, budgetError("compression ratio limit reached")
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
					return nil, readErr
				}
				if errors.Is(readErr, ErrCompressedEntryLimit) {
					return nil, budgetError(fmt.Sprintf("read archive entry: %v", readErr))
				}
				return nil, formatError("read archive entry: %v", readErr)
			}
			break
		}
	}
	if file.Method == zip.Deflate {
		if _, err := io.Copy(io.Discard, counter); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			if errors.Is(err, ErrCompressedEntryLimit) {
				return nil, budgetError(fmt.Sprintf("consume compressed entry: %v", err))
			}
			return nil, formatError("consume compressed entry: %v", err)
		}
	}
	if counter.BytesRead() > limits.MaxCompressedBytes {
		return nil, budgetError("entry compressed byte limit reached")
	}
	if CompressionRatioExceeded(entryExpanded, counter.BytesRead(), limits.RatioFloor, limits.MaxRatio) {
		return nil, budgetError("compression ratio limit reached")
	}
	if uint64(entryExpanded) != file.UncompressedSize64 {
		return nil, formatError("archive entry expanded size mismatch")
	}
	if checksum.Sum32() != file.CRC32 {
		return nil, formatError("archive entry CRC mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
