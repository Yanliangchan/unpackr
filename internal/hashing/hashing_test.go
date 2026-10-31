package hashing

import (
	"strings"
	"testing"
)

func TestKnownVectors(t *testing.T) {
	h, n, err := Sum(strings.NewReader("abc"))
	if err != nil || n != 3 {
		t.Fatal(err, n)
	}
	if h.MD5 != "900150983cd24fb0d6963f7d28e17f72" ||
		h.SHA1 != "a9993e364706816aba3e25717850c26c9cd0d89d" ||
		h.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("%+v", h)
	}
	h, _, _ = Sum(strings.NewReader(""))
	if h.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty input")
	}
}
