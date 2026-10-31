// Package assets embeds the files shipped inside the binary.
package assets

import "embed"

// ArtVault holds the built-in banners.
//
//go:embed artvault/*.txt
var ArtVault embed.FS
