package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	stdpe "debug/pe"
	"fmt"
	"math/rand"
	"os"
	"time"

	gomacho "github.com/blacktop/go-macho"
	"github.com/saferwall/pe"
)

type res struct{ ok, err, panics, hang int }

func try(name string, f func() error, r *res) {
	done := make(chan string, 1)
	go func() {
		defer func() {
			if x := recover(); x != nil {
				done <- "panic"
			}
		}()
		if e := f(); e != nil {
			done <- "err"
		} else {
			done <- "ok"
		}
	}()
	select {
	case s := <-done:
		switch s {
		case "ok":
			r.ok++
		case "err":
			r.err++
		case "panic":
			r.panics++
		}
	case <-time.After(5 * time.Second):
		r.hang++
	}
}

func main() {
	files := os.Args[2:]
	n := 0
	fmt.Sscan(os.Args[1], &n)
	rng := rand.New(rand.NewSource(1))
	results := map[string]*res{}
	get := func(k string) *res {
		if results[k] == nil {
			results[k] = &res{}
		}
		return results[k]
	}
	for _, f := range files {
		orig, _ := os.ReadFile(f)
		for i := 0; i < n; i++ {
			b := append([]byte(nil), orig...)
			// mutate only header region (first 4KB) heavily, plus some random
			k := 1 + rng.Intn(16)
			for j := 0; j < k; j++ {
				lim := 4096
				if len(b) < lim {
					lim = len(b)
				}
				b[rng.Intn(lim)] = byte(rng.Intn(256))
			}
			if rng.Intn(6) == 0 {
				b = b[:rng.Intn(len(b))]
			}
			switch {
			case bytes.HasPrefix(orig, []byte("MZ")):
				try("pe", func() error {
					p, e := pe.NewBytes(b, &pe.Options{Fast: false})
					if e != nil {
						return e
					}
					defer p.Close()
					if e := p.Parse(); e != nil {
						return e
					}
					_ = p.Imports
					return nil
				}, get("saferwall/pe"))
				try("stdpe", func() error {
					p, e := stdpe.NewFile(bytes.NewReader(b))
					if e != nil {
						return e
					}
					_, _ = p.ImportedSymbols()
					return nil
				}, get("debug/pe"))
			case bytes.HasPrefix(orig, []byte("\x7fELF")):
				try("elf", func() error {
					p, e := elf.NewFile(bytes.NewReader(b))
					if e != nil {
						return e
					}
					_, _ = p.ImportedSymbols()
					_, _ = p.DynamicSymbols()
					return nil
				}, get("debug/elf"))
			default:
				try("macho", func() error {
					p, e := macho.NewFile(bytes.NewReader(b))
					if e != nil {
						return e
					}
					_, _ = p.ImportedSymbols()
					return nil
				}, get("debug/macho"))
				try("gomacho", func() error {
					p, e := gomacho.NewFile(bytes.NewReader(b))
					if e != nil {
						return e
					}
					_ = p.Symtab
					return nil
				}, get("blacktop/go-macho"))
			}
		}
	}
	for k, v := range results {
		fmt.Printf("%-20s ok=%d err=%d panic=%d hang=%d\n", k, v.ok, v.err, v.panics, v.hang)
	}
}
