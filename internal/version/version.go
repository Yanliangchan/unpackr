// Package version holds build metadata set at link time.
package version

import (
	"fmt"
	"runtime"
)

// Version is overridden with -ldflags "-X .../version.Version=...".
var Version = "0.1.0-dev"

const Name = "UNPACKR"
const Tagline = "Know What's Inside."

// Platform returns "os/arch".
func Platform() string { return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH) }
