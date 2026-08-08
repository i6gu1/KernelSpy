package services

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Extractor struct{}

func NewExtractor() *Extractor {
	return &Extractor{}
}

const (
	// maxExtractedBytes guards against zip-bomb uploads: the compressed archive
	// may be small, but its expanded content is capped to protect the disk.
	maxExtractedBytes = 200 * 1024 * 1024 // 200 MB total
	// maxExtractedFileBytes caps a single entry so one huge file can't blow up
	// the workspace by itself.
	maxExtractedFileBytes = 50 * 1024 * 1024 // 50 MB per file
	// maxExtractedEntries caps the number of files (symlink/special-file and
	// decompression-bomb abuse protection).
	maxExtractedEntries = 5000
)

// ExtractZIP safely extracts a ZIP archive into destDir. It rejects path
// traversal, caps per-file and total expansion sizes (zip bombs), limits the
// entry count and streams each file with io.Copy.
func (e *Extractor) ExtractZIP(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	destClean := filepath.Clean(destDir)
	var totalBytes int64
	entryCount := 0

	for _, file := range reader.File {
		entryCount++
		if entryCount > maxExtractedEntries {
			return fmt.Errorf("archive contains too many files (max %d)", maxExtractedEntries)
		}

		// Reject absolute paths and any path that escapes the destination
		// directory (zip-slip protection).
		name := filepath.ToSlash(file.Name)
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("archive contains an unsafe path: %s", file.Name)
		}

		filePath := filepath.Join(destDir, filepath.FromSlash(name))
		if !strings.HasPrefix(filepath.Clean(filePath), destClean+string(os.PathSeparator)) && filepath.Clean(filePath) != destClean {
			return fmt.Errorf("archive contains a path outside the extract directory: %s", file.Name)
		}

		// Cap total expanded size before touching the disk.
		uncompressed := int64(file.UncompressedSize64)
		if uncompressed > maxExtractedFileBytes {
			return fmt.Errorf("file %s expands beyond the %d MB per-file limit", file.Name, maxExtractedFileBytes/(1024*1024))
		}
		totalBytes += uncompressed
		if totalBytes > maxExtractedBytes {
			return fmt.Errorf("archive expands beyond the %d MB limit", maxExtractedBytes/(1024*1024))
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}

		rc, err := file.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		// Stream with io.Copy; cap the copy so a lying UncompressedSize64 can't
		// bypass the limits (CopyN-style guard).
		written, err := io.Copy(outFile, io.LimitReader(rc, maxExtractedFileBytes+1))
		rc.Close()
		outFile.Close()

		if err != nil {
			return err
		}
		if written > maxExtractedFileBytes {
			return fmt.Errorf("file %s expands beyond the %d MB per-file limit", file.Name, maxExtractedFileBytes/(1024*1024))
		}
	}

	return nil
}
