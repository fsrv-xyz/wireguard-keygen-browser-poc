// Package profile rewrites a profile zip, replacing the <PRIVATEKEY>
// placeholder in its files with a generated key.
package profile

import (
	"archive/zip"
	"bytes"
	"io"
)

// Placeholder is the marker in the profile zip that gets replaced
// by the private key.
const Placeholder = "<PRIVATEKEY>"

// WithKey rewrites the zip, replacing every Placeholder occurrence in
// each file with key, and returns the new zip bytes.
func WithKey(data []byte, key string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	w := zip.NewWriter(&out)
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
		if _, err := dst.Write(bytes.ReplaceAll(content, []byte(Placeholder), []byte(key))); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
