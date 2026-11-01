# Workflows

`ci.yml` runs vet, the full test suite with the race detector, golangci-lint
and amd64/arm64 builds. Tests that need optional tools (UPX, YARA-X, rustc,
PyInstaller) skip when the tool is absent; the workflow installs them so they
run. This file has not yet been exercised on GitHub-hosted runners: confirm the
first run, in particular the arm64 job and the YARA-X build cache.
