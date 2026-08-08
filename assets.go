// Package assets embeds the static site (templates, CSS/JS/images and
// translation files) into the Go binary. This is required on Vercel, where
// serverless Go functions have a read-only filesystem and the only files
// available at runtime are the ones compiled into the binary.
package assets

import (
	"embed"
	"io/fs"
)

//go:embed templates static i18n/*.json
var embedded embed.FS

// Templates returns the embedded templates directory.
func Templates() fs.FS {
	sub, err := fs.Sub(embedded, "templates")
	if err != nil {
		panic(err)
	}
	return sub
}

// Static returns the embedded static directory (CSS, JS, images, client i18n).
func Static() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

// I18n returns the embedded server-side translation files.
func I18n() fs.FS {
	sub, err := fs.Sub(embedded, "i18n")
	if err != nil {
		panic(err)
	}
	return sub
}
