// Package disk writes files that must survive power loss. Routers are cut
// off without a shutdown as a matter of course; a plain write-then-rename
// can be journaled with the data blocks not yet written, leaving an empty
// file. Here the data is synced before the rename and the directory entry
// afterwards.
package disk

import (
	"os"
	"path/filepath"
)

// Write replaces path with data atomically and durably. On failure the
// previous file is left untouched.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	switch {
	case werr != nil:
		err = werr
	case serr != nil:
		err = serr
	default:
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	// Make the rename itself durable: sync the directory.
	if d, derr := os.Open(filepath.Dir(path)); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
