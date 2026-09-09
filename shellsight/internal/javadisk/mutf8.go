package javadisk

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

func decodeModifiedUTF8(data []byte) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(data))
	var highSurrogate uint16

	writeUnit := func(unit uint16, offset int) error {
		if highSurrogate != 0 {
			if unit < 0xdc00 || unit > 0xdfff {
				return fmt.Errorf("modified UTF-8 at byte offset %d has an unpaired high surrogate", offset)
			}
			decoded.WriteRune(utf16.DecodeRune(rune(highSurrogate), rune(unit)))
			highSurrogate = 0
			return nil
		}
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			highSurrogate = unit
		case unit >= 0xdc00 && unit <= 0xdfff:
			return fmt.Errorf("modified UTF-8 at byte offset %d has an unpaired low surrogate", offset)
		default:
			decoded.WriteRune(rune(unit))
		}
		return nil
	}

	for offset := 0; offset < len(data); {
		start := offset
		first := data[offset]
		var unit uint16
		switch {
		case first == 0:
			return "", fmt.Errorf("modified UTF-8 at byte offset %d contains a raw NUL", offset)
		case first <= 0x7f:
			unit = uint16(first)
			offset++
		case first&0xe0 == 0xc0:
			if offset+1 >= len(data) {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has a truncated two-byte sequence", offset)
			}
			second := data[offset+1]
			if second&0xc0 != 0x80 {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has an invalid continuation byte", offset+1)
			}
			unit = uint16(first&0x1f)<<6 | uint16(second&0x3f)
			if unit == 0 {
				if first != 0xc0 || second != 0x80 {
					return "", fmt.Errorf("modified UTF-8 at byte offset %d has an invalid NUL encoding", offset)
				}
			} else if unit < 0x80 {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has an overlong encoding", offset)
			}
			offset += 2
		case first&0xf0 == 0xe0:
			if offset+2 >= len(data) {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has a truncated three-byte sequence", offset)
			}
			second, third := data[offset+1], data[offset+2]
			if second&0xc0 != 0x80 {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has an invalid continuation byte", offset+1)
			}
			if third&0xc0 != 0x80 {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has an invalid continuation byte", offset+2)
			}
			unit = uint16(first&0x0f)<<12 | uint16(second&0x3f)<<6 | uint16(third&0x3f)
			if unit < 0x800 {
				return "", fmt.Errorf("modified UTF-8 at byte offset %d has an overlong encoding", offset)
			}
			offset += 3
		default:
			return "", fmt.Errorf("modified UTF-8 at byte offset %d has an invalid leading byte 0x%02x", offset, first)
		}
		if err := writeUnit(unit, start); err != nil {
			return "", err
		}
	}
	if highSurrogate != 0 {
		return "", fmt.Errorf("modified UTF-8 at byte offset %d has an unpaired high surrogate", len(data))
	}
	return decoded.String(), nil
}
