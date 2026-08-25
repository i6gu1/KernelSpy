// imginfo prints dimensions and format info for the design-reference images
// in the "ui pic" folders so the desktop app can embed them appropriately.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func jpegSize(p string) (int, int) {
	f, err := os.Open(p)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	b := make([]byte, 4096)
	n, _ := f.Read(b)
	b = b[:n]
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return 0, 0
	}
	i := 2
	for i < len(b)-9 {
		if b[i] != 0xFF {
			i++
			continue
		}
		marker := b[i+1]
		if marker == 0xC0 || marker == 0xC1 || marker == 0xC2 {
			h := int(binary.BigEndian.Uint16(b[i+5 : i+7]))
			w := int(binary.BigEndian.Uint16(b[i+7 : i+9]))
			return w, h
		}
		i += 2 + int(binary.BigEndian.Uint16(b[i+2:i+4]))
	}
	return 0, 0
}

func pngSize(p string) (int, int) {
	f, err := os.Open(p)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	b := make([]byte, 24)
	if _, err := f.Read(b); err != nil {
		return 0, 0
	}
	if len(b) < 24 || string(b[:8]) != "\x89PNG\r\n\x1a\n" {
		return 0, 0
	}
	return int(binary.BigEndian.Uint32(b[16:20])), int(binary.BigEndian.Uint32(b[20:24]))
}

func main() {
	for _, dir := range []string{"kenelspy.exe/ui pic", "ui pic", "static/ui/pic"} {
		fmt.Println("==", dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Println("  err", err)
			continue
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			info, _ := os.Stat(p)
			if info == nil {
				continue
			}
			var w, h int
			lower := strings.ToLower(e.Name())
			switch {
			case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
				w, h = jpegSize(p)
			case strings.HasSuffix(lower, ".png"):
				w, h = pngSize(p)
			}
			fmt.Printf("  %-50s %7d bytes  %dx%d\n", e.Name(), info.Size(), w, h)
		}
	}
}
