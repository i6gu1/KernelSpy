package services

import "os"

// removeFile best-effort deletes a temporary file.
func removeFile(path string) {
	if path != "" {
		os.Remove(path)
	}
}
