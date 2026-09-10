package profile

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readZip(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		src, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(src)
		src.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(content)
	}
	return out
}

func TestWithKey(t *testing.T) {
	const key = "YQ0y87J9wR5c5x6nJx7b6d5c0k3n9a"
	in := zipBytes(t, map[string]string{
		"wg0.conf":   "PrivateKey = " + Placeholder + "\ntest124\n",
		"README.txt": "no marker here\n",
	})
	got, err := WithKey(in, key)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"wg0.conf":   "PrivateKey = " + key + "\ntest124\n",
		"README.txt": "no marker here\n",
	}
	if !reflect.DeepEqual(readZip(t, got), want) {
		t.Fatalf("got %v, want %v", readZip(t, got), want)
	}
}

func TestWithKeyNoPlaceholder(t *testing.T) {
	in := zipBytes(t, map[string]string{"wg0.conf": "PrivateKey = abc\n"})

	if _, err := WithKey(in, "some-key"); !errors.Is(err, ErrNoPlaceholder) {
		t.Fatalf("got %v, want ErrNoPlaceholder", err)
	}
}

func TestWithKeyCorruptZip(t *testing.T) {
	if _, err := WithKey([]byte("not a zip"), "k"); err == nil {
		t.Fatal("want error")
	}
}
