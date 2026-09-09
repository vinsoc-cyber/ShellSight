package main

import (
	"os"
	"os/exec"
	"strings"
)

// parseJavaPaths splits a newline-separated list of java.exe paths, trimming
// whitespace/CR and dropping blanks. Used to parse the PowerShell process query.
func parseJavaPaths(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// firstExistingFile returns the first path that exists on disk, or "".
func firstExistingFile(paths []string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// runningJVMJava returns the java.exe of a currently-running JVM (the most
// reliable launcher for an attach, since it matches a real target), or "".
// Windows-only; uses CIM so it works without wmic.
func runningJVMJava() string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-CimInstance Win32_Process -Filter "Name='java.exe'" | `+
			`Select-Object -ExpandProperty ExecutablePath`)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return firstExistingFile(parseJavaPaths(string(out)))
}
