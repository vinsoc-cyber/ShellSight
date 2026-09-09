package main

import (
	"fmt"
	"io"
	"os"

	"shellsight/internal/javadisk"
)

const maxJavaPolicyBytes = 64 << 10

func loadJavaOptions(path string) (javadisk.Options, error) {
	if path == "" {
		return javadisk.DefaultOptions(), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return javadisk.Options{}, fmt.Errorf("open policy: %w", err)
	}
	defer file.Close()

	reader := &io.LimitedReader{R: file, N: maxJavaPolicyBytes + 1}
	data, err := io.ReadAll(reader)
	if err != nil {
		return javadisk.Options{}, fmt.Errorf("read policy: %w", err)
	}
	if len(data) > maxJavaPolicyBytes {
		return javadisk.Options{}, fmt.Errorf("policy exceeds %d-byte limit", maxJavaPolicyBytes)
	}
	opts, err := javadisk.ParseOptionsJSON(data)
	if err != nil {
		return javadisk.Options{}, fmt.Errorf("parse policy: %w", err)
	}
	return opts, nil
}
