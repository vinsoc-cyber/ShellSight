package safearchive

import (
	"fmt"
	"path"
	"strings"
)

// NormalizePath canonicalizes an archive member name without consulting the
// host filesystem.
func NormalizePath(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	replaced := strings.ReplaceAll(name, `\`, "/")
	if replaced == "" || replaced == "." || strings.HasPrefix(replaced, "/") ||
		isDriveQualified(replaced) {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	cleaned := path.Clean(replaced)
	if cleaned == "" || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	return cleaned, nil
}

func isDriveQualified(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	return name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z'
}
