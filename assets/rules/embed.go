// Package rules embeds the built-in YARA rule files. It is separate from the
// ArtVault assets so the analysis engine can use rules without depending on
// presentation assets.
package rules

import "embed"

// FS holds the *.yar files.
//
//go:embed *.yar
var FS embed.FS
