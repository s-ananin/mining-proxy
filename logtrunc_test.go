package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// Файл с O_APPEND (как nohup.out): после очистки запись идёт с начала,
// размер — только новые данные.
func TestTruncateOutputAppend(t *testing.T) {
	dir := tempDir(t)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "nohup.out")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("old log line\n"); err != nil {
		t.Fatal(err)
	}
	truncateOutput(f)
	if _, err := f.WriteString("new\n"); err != nil {
		t.Fatal(err)
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new\n" {
		t.Errorf("содержимое после очистки = %q, want %q", data, "new\n")
	}
}

// Файл без O_APPEND ("> file"): без Seek файл стал бы дырявым.
func TestTruncateOutputNoAppend(t *testing.T) {
	dir := tempDir(t)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "out.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("old log line\n"); err != nil {
		t.Fatal(err)
	}
	truncateOutput(f)
	if _, err := f.WriteString("new\n"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 4 {
		t.Errorf("размер после очистки = %d, want 4", fi.Size())
	}
}

// tempDir — замена t.TempDir (go.mod на go 1.13).
func tempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "logtrunc")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
