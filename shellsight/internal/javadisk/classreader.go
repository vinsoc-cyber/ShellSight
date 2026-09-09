package javadisk

import (
	"encoding/binary"
	"fmt"
)

type classReader struct {
	data []byte
	off  int
}

func (r *classReader) u1() (uint8, error) {
	data, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func (r *classReader) u2() (uint16, error) {
	data, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(data), nil
}

func (r *classReader) u4() (uint32, error) {
	data, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

func (r *classReader) u8() (uint64, error) {
	data, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data), nil
}

func (r *classReader) bytes(n uint32) ([]byte, error) {
	remaining := len(r.data) - r.off
	if uint64(n) > uint64(remaining) {
		return nil, fmt.Errorf("class read at byte offset %d needs %d bytes, only %d remain", r.off, n, remaining)
	}
	end := r.off + int(n)
	data := r.data[r.off:end]
	r.off = end
	return data, nil
}

func (r *classReader) skip(n uint32) error {
	_, err := r.bytes(n)
	return err
}

func (r *classReader) remaining() int {
	return len(r.data) - r.off
}
