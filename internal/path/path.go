package path

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ToModuleRoot returns the absolute path to the project root by walking
// up from this file's location until a go.mod file is found.
func ToModuleRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("could not determine source file path via runtime.Caller")
	}

	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("project root not found (no go.mod in any parent directory)")
		}
		dir = parent
	}
}
