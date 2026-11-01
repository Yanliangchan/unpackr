//go:build !unix && !windows

package database

import "time"

// On platforms without file locking the store relies on one UNPACKR process
// at a time.
type fileLock struct{}

func lockFile(string, time.Duration) (*fileLock, error) { return &fileLock{}, nil }

func (l *fileLock) unlock() {}
