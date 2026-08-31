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
	candidateDevices = bsdCandidateDevices
	mountCidata = bsdMountCidata
}

// bsdMountCidata enumerates common cidata device paths and tries
// mounting each as cd9660 (iso9660) then msdos, read-only, until one
// yields a /user-data file.
//
// This is the fallback path : it runs only when the unprivileged direct
// read in disk.go found nothing on any candidate. It forks
// /sbin/mount_* and needs root, which is why it is no longer the first
// thing tried.
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

// bsdCandidateDevices returns the paths to scan. Per-OS because the
// device naming conventions diverge and there is no udev-style
// /dev/disk/by-label/ to dispatch on. We include both raw (c-partition
// / whole disk) and partitioned forms because cidata images come in
// both shapes depending on the tool used to mint them.
//
// The list is unchanged from the mount-era code : what changed is what
// we do with each entry (open and read, rather than mount).
func bsdCandidateDevices() []string {
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
