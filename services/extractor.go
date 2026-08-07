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

// maxExtractedBytes guards against zip-bomb uploads: the compressed archive may
// be small, but its expanded content is capped to protect the container disk.
const maxExtractedBytes = 200 * 1024 * 1024 // 200 MB

func (e *Extractor) ExtractZIP(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	var totalBytes int64

	for _, file := range reader.File {
		filePath := filepath.Join(destDir, file.Name)

		if !strings.HasPrefix(filePath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return err
		}

		// Zip-bomb guard: cap the total expanded size.
		totalBytes += int64(file.UncompressedSize64)
		if totalBytes > maxExtractedBytes {
			return fmt.Errorf("archive expands beyond the %d MB limit", maxExtractedBytes/(1024*1024))
		}

		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}

		rc, err := file.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
