// Package hashing computes the file digests in a single pass.
package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Sum reads r to EOF and returns its digests and length.
func Sum(r io.Reader) (models.Hashes, int64, error) {
	m, s1, s256 := md5.New(), sha1.New(), sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(m, s1, s256), r, make([]byte, 1<<20))
	if err != nil {
		return models.Hashes{}, n, err
	}
	return models.Hashes{
		MD5:    hex.EncodeToString(m.Sum(nil)),
		SHA1:   hex.EncodeToString(s1.Sum(nil)),
		SHA256: hex.EncodeToString(s256.Sum(nil)),
	}, n, nil
}
