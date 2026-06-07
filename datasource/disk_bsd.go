//go:build openbsd || freebsd || netbsd

package datasource

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func init() {
	mountCidata = bsdMountCidata
}

// bsdMountCidata enumerates common cidata device paths and tries
// mounting each as cd9660 (iso9660) read-only until one yields a
// /user-data file.
//
// The BSDs don't have udev-style /dev/disk/by-label/, so we can't
// dispatch on label cheaply. We walk a per-OS candidate list of
// likely virtio-cd / disk nodes. The qemu virtio-blk device for a
// second cidata image typically lands at sd1 (OpenBSD) or vtbd1
// (FreeBSD) or wd1 (NetBSD raw IDE).
func bsdMountCidata() (string, func(), error) {
	candidates := candidateDevices()
	mnt, err := os.MkdirTemp("", "weft-firstboot-cidata-")
	if err != nil {
		return "", nil, fmt.Errorf("mkdtemp: %w", err)
	}
	cleanup := func() {
		_ = exec.Command("/sbin/umount", mnt).Run()
		_ = os.RemoveAll(mnt)
	}
	for _, dev := range candidates {
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		// Try cd9660 first (cloud-init's default), then msdos as
		// a fallback for VFAT-formatted seed disks.
		for _, fstype := range []string{"cd9660", "msdos"} {
			cmd := mountCmd(fstype, dev, mnt)
			if err := cmd.Run(); err != nil {
				continue
			}
			// Mount succeeded ; confirm it has the right shape.
			if _, err := os.Stat(filepath.Join(mnt, "user-data")); err == nil {
				return mnt, cleanup, nil
			}
			// Wrong filesystem -- unmount and try the next pair.
			_ = exec.Command("/sbin/umount", mnt).Run()
		}
	}
	cleanup()
	return "", nil, errors.New("no cidata-shaped disk found among candidate devices")
}

// candidateDevices returns the paths to scan. Per-OS because the device
// naming conventions diverge. We include both raw (c-partition / whole
// disk) and partitioned forms because cidata images come in both shapes
// depending on the tool used to mint them.
func candidateDevices() []string {
	switch runtime.GOOS {
	case "openbsd":
		return []string{
			"/dev/sd1c", "/dev/sd1a",
			"/dev/sd2c", "/dev/sd2a",
			"/dev/cd0c", "/dev/cd0a",
			"/dev/cd1c", "/dev/cd1a",
		}
	case "freebsd":
		return []string{
			"/dev/cd0", "/dev/cd1",
			"/dev/vtbd1", "/dev/vtbd2",
			"/dev/da1", "/dev/da2",
		}
	case "netbsd":
		return []string{
			"/dev/cd0a", "/dev/cd1a",
			"/dev/sd1a", "/dev/sd2a",
			"/dev/wd1a", "/dev/wd2a",
		}
	}
	return nil
}

// mountCmd builds the per-OS mount invocation. OpenBSD/NetBSD use
// dedicated `mount_<fs>` binaries ; FreeBSD uses `mount -t <fs>`.
// The returned *exec.Cmd is ready to Run().
func mountCmd(fstype, dev, mnt string) *exec.Cmd {
	switch runtime.GOOS {
	case "openbsd", "netbsd":
		return exec.Command("/sbin/mount_"+fstype, "-o", "ro", dev, mnt)
	case "freebsd":
		return exec.Command("/sbin/mount", "-t", fstype, "-o", "ro", dev, mnt)
	}
	// Defensive : we shouldn't be invoked on a non-BSD due to the
	// build tag, but a default keeps the function total.
	return exec.Command("mount", dev, mnt)
}
