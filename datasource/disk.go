package datasource

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// fromDisk locates a NoCloud cidata disk. The cross-platform contract :
// the disk has a filesystem (iso9660, vfat, or msdos) with the volume
// label "cidata" or "CIDATA" containing /user-data (and optionally
// /meta-data, which we don't currently consume — hostname comes from
// user-data's Hostname field).
//
// The mount strategy is per-OS (see disk_<os>.go) ; this layer just
// invokes the locator and reads files from the returned mount point.
func fromDisk() (Source, error) {
	mnt, cleanup, err := mountCidata()
	if err != nil {
		return Source{}, fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	defer cleanup()
	raw, err := os.ReadFile(filepath.Join(mnt, "user-data"))
	if err != nil {
		return Source{}, fmt.Errorf("%w: read user-data from %s: %v", ErrNotFound, mnt, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Source{}, err
	}
	return Source{
		Origin: "nocloud:" + mnt,
		Raw:    raw,
		Config: cfg,
	}, nil
}

// mountCidata locates and mounts a cidata disk, returning the mount
// point and a cleanup func to unmount + rmdir. Implemented per-OS via
// build tags ; the default stub below kicks in on platforms we don't
// yet support so the package still compiles for darwin builds + tests.
var mountCidata = func() (string, func(), error) {
	return "", func() {}, errors.New("cidata disk discovery not implemented on this platform")
}
