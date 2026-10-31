# UNPACKR build targets.
GO      ?= go
BIN     := bin/unpackr
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X github.com/Yanliangchan/unpackr/internal/version.Version=$(VERSION)
PREFIX  ?= /usr/local

.PHONY: build test lint fuzz install uninstall clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/unpackr

test:
	$(GO) vet ./...
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

fuzz:
	$(GO) test ./internal/identification -run '^$$' -fuzz FuzzIdentify -fuzztime 30s

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/unpackr

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/unpackr

clean:
	rm -rf bin dist
