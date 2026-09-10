// Package profile rewrites a profile zip, replacing the <PRIVATEKEY>
// placeholder in its files with a generated key.
package profile

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
)

// Placeholder is the marker in the profile zip that gets replaced
// by the private key.
const Placeholder = "<PRIVATEKEY>"

// ErrNoPlaceholder reports a profile zip that carries no Placeholder, so
// the result would not contain the key.
var ErrNoPlaceholder = errors.New("profile zip contains no " + Placeholder)

// WithKey rewrites the zip, replacing every Placeholder occurrence in
// each file with key, and returns the new zip bytes. It reports
// ErrNoPlaceholder when no file carried the marker.
func WithKey(data []byte, key string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	w := zip.NewWriter(&out)
	replaced := 0
	for _, f := range zr.File {
		src, err := f.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(src)
		src.Close()
		if err != nil {
			return nil, err
		}

		dst, err := w.CreateHeader(&f.FileHeader)
		if err != nil {
			return nil, err
		}
		replaced += bytes.Count(content, []byte(Placeholder))
		if _, err := dst.Write(bytes.ReplaceAll(content, []byte(Placeholder), []byte(key))); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if replaced == 0 {
		return nil, ErrNoPlaceholder
	}
	return out.Bytes(), nil
}
