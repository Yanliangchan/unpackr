# UNPACKR build targets.
GO      ?= go
BIN     := bin/unpackr
VERSION ?= 0.1.0
LDFLAGS := -s -w -X github.com/Yanliangchan/unpackr/internal/version.Version=$(VERSION)
PREFIX  ?= /usr/local

.PHONY: build test lint fuzz install uninstall clean package

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

package:
	packaging/build-deb.sh $(VERSION) amd64
	packaging/build-deb.sh $(VERSION) arm64
	cd dist && sha256sum *.deb > SHA256SUMS

clean:
	rm -rf bin dist
