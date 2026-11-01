# Third-party components

UNPACKR is Apache-2.0. The binary statically links the Go dependencies listed
in `go.mod`. Run `go list -m all` for the exact versions of a given build.
Licences were checked during verification (see `docs/VERIFICATION.md`); the
authoritative text for each module is in its upstream repository.

Direct dependencies include: spf13/cobra, gopkg.in/yaml.v3, modernc.org/sqlite,
saferwall/pe, glaslos/ssdeep, glaslos/tlsh, landlock-lsm/go-landlock and
elastic/go-seccomp-bpf.

External programs (`upx`, `yr`/YARA-X) are **not** bundled in this package.
They are discovered on `PATH` at run time and executed only inside the
confined exec worker.
