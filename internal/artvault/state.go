package artvault

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LastShown reads the id of the previously displayed banner, if any.
func LastShown(stateDir string) string {
	if stateDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "last_banner"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// RememberShown stores id. Failures are ignored: remembering is cosmetic.
func RememberShown(stateDir, id string) {
	if stateDir == "" {
		return
	}
	if os.MkdirAll(stateDir, 0o700) == nil {
		_ = os.WriteFile(filepath.Join(stateDir, "last_banner"), []byte(id+"\n"), 0o600)
	}
}

// Favourites returns the saved favourite ids.
func Favourites(configDir string) []string {
	if configDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(configDir, "favourites"))
	if err != nil {
		return nil
	}
	var ids []string
	for _, l := range strings.Fields(string(b)) {
		ids = append(ids, l)
	}
	sort.Strings(ids)
	return ids
}

// AddFavourite records id (idempotent).
func AddFavourite(configDir, id string) error {
	for _, f := range Favourites(configDir) {
		if f == id {
			return nil
		}
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}
	ids := append(Favourites(configDir), id)
	sort.Strings(ids)
	return os.WriteFile(filepath.Join(configDir, "favourites"), []byte(strings.Join(ids, "\n")+"\n"), 0o600)
}
