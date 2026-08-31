//go:build linux

package datasource

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	candidateDevices = linuxCandidateDevices
	mountCidata = linuxMountCidata
}

// linuxCandidateDevices lists the nodes to try, most likely first.
//
// udev's by-label symlinks are the precise answer and come first : they
// name the filesystem label the NoCloud contract specifies, whatever the
// filesystem type or the disk's position on the bus.
//
// The bare nodes after them exist because by-label is not universal —
// a guest booted without udev (a minimal initramfs, a container-ish
// rootfs, an early rc stage) has an empty /dev/disk/. Under the old
// mount-based code such a guest found nothing at all. Trying the usual
// virtio / SCSI / ATAPI seats costs a read-only open and a handful of
// bounded reads each, and the candidate is only accepted once
// /user-data has actually been read out of it, so a wrong guess is
// discarded rather than acted on.
func linuxCandidateDevices() []string {
	return []string{
		"/dev/disk/by-label/cidata",
		"/dev/disk/by-label/CIDATA",
		"/dev/sr0", "/dev/sr1",
		"/dev/vdb", "/dev/vdc",
		"/dev/sdb", "/dev/sdc",
	}
}

// linuxMountCidata walks /dev/disk/by-label/ for cidata / CIDATA and mounts
// it read-only on a temp dir. udev populates by-label/ symlinks for every
// labeled filesystem on the system, regardless of FS type — covers
// iso9660 (most common for cidata), vfat (sometimes), and ext4 (rare).
//
// This is the fallback path : it runs only when the unprivileged direct
// read in disk.go found nothing. It needs CAP_SYS_ADMIN, which is why it
// is no longer the first thing tried.
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
