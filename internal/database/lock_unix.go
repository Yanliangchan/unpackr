//go:build unix

package database

import (
	"errors"
	"os"
	"syscall"
	"time"
)

type fileLock struct{ f *os.File }

// lockFile takes an exclusive advisory lock that the kernel drops if the
// process dies, so a crash never leaves the database locked.
func lockFile(path string, wait time.Duration) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // beside the configured database
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // fd fits int
		if err == nil {
			return &fileLock{f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrBusy
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (l *fileLock) unlock() { _ = l.f.Close() } // closing releases the lock
