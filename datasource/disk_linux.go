//go:build linux

package datasource

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	mountCidata = linuxMountCidata
}

// linuxMountCidata walks /dev/disk/by-label/ for cidata / CIDATA and mounts
// it read-only on a temp dir. udev populates by-label/ symlinks for every
// labeled filesystem on the system, regardless of FS type — covers
// iso9660 (most common for cidata), vfat (sometimes), and ext4 (rare).
//
// The filesystem type is auto-detected via the kernel's filesystems list :
// we try iso9660 first (cloud-init's default for cidata) then vfat. If
// /proc/filesystems isn't readable (extremely unusual) we just pass an
// empty type and let the kernel guess.
func linuxMountCidata() (string, func(), error) {
	candidates := []string{
		"/dev/disk/by-label/cidata",
		"/dev/disk/by-label/CIDATA",
	}
	var dev string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			dev = c
			break
		}
	}
	if dev == "" {
		return "", nil, errors.New("no /dev/disk/by-label/cidata")
	}
	mnt, err := os.MkdirTemp("", "weft-firstboot-cidata-")
	if err != nil {
		return "", nil, fmt.Errorf("mkdtemp: %w", err)
	}
	cleanup := func() {
		_ = unix.Unmount(mnt, 0)
		_ = os.RemoveAll(mnt)
	}
	for _, fs := range []string{"iso9660", "vfat"} {
		if err := unix.Mount(dev, mnt, fs, unix.MS_RDONLY|unix.MS_NOATIME, ""); err == nil {
			return mnt, cleanup, nil
		}
	}
	cleanup()
	return "", nil, fmt.Errorf("could not mount %s as iso9660 or vfat", dev)
}

