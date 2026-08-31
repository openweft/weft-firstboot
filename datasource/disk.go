package datasource

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/go-filesystems/detect"
	"github.com/go-filesystems/detect/fat32reg"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/iso9660"
)

// fromDisk locates a NoCloud cidata disk. The cross-platform contract :
// the disk carries a filesystem (iso9660 or vfat/FAT32) holding
// /user-data (and optionally /meta-data, which we don't currently
// consume — hostname comes from user-data's Hostname field).
//
// Two strategies, tried in that order :
//
//  1. Direct read (preferred). We open each candidate device read-only,
//     probe its magic signature with go-filesystems/detect, and read
//     /user-data straight out of the on-disk structures with the pure-Go
//     driver. No mount(2), no /sbin/mount_* fork, no root.
//
//  2. Mount fallback (last resort). Only if step 1 found nothing on any
//     candidate. This is the historic path and is kept because the
//     kernel drivers cover shapes the pure-Go drivers do not yet read —
//     notably FAT12/FAT16 seeds (mkfs.vfat's default on images below
//     ~33 MiB), which go-filesystems/fat32 rejects by design, and any
//     other labelled filesystem udev exposes (ext4 seeds are rare but
//     legal). Dropping it would be a regression on those disks.
//
// Which of the two served is recorded in Source.Origin — "(iso9660,
// direct)" versus "(mount fallback)" — so the boot log and the sentinel
// file say plainly whether the unprivileged path worked. A fallback
// that nobody can see is a regression nobody can find.
func fromDisk() (Source, error) {
	if src, err := fromDiskDirect(); err == nil {
		return src, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Source{}, err
	}
	return fromDiskMount()
}

// fromDiskDirect walks the candidate devices and returns the first one
// that opens, probes as a filesystem we can read, and holds /user-data.
// Every other outcome — absent node, permission denied, unrecognised or
// truncated image, a filesystem with no /user-data — moves on to the
// next candidate rather than aborting the whole probe.
func fromDiskDirect() (Source, error) {
	for _, dev := range candidateDevices() {
		raw, typ, err := readCidataFile(dev, userDataName)
		if err != nil {
			continue
		}
		cfg, err := Parse(raw)
		if err != nil {
			// The disk IS the cidata disk (it has /user-data) but the
			// payload doesn't parse. That is a hard error, not a
			// "keep looking" : silently falling through to HTTP would
			// apply the wrong configuration.
			return Source{}, err
		}
		return Source{
			Origin: fmt.Sprintf("nocloud:%s (%s, direct)", dev, typ),
			Raw:    raw,
			Config: cfg,
		}, nil
	}
	return Source{}, fmt.Errorf("%w: no readable cidata filesystem among candidate devices", ErrNotFound)
}

// fromDiskMount is the historic mount-based path, now the fallback.
func fromDiskMount() (Source, error) {
	mnt, cleanup, err := mountCidata()
	if err != nil {
		return Source{}, fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	defer cleanup()
	raw, err := os.ReadFile(path.Join(mnt, userDataName))
	if err != nil {
		return Source{}, fmt.Errorf("%w: read %s from %s: %v", ErrNotFound, userDataName, mnt, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Source{}, err
	}
	return Source{
		Origin: fmt.Sprintf("nocloud:%s (mount fallback)", mnt),
		Raw:    raw,
		Config: cfg,
	}, nil
}

// userDataName is the file every NoCloud seed must carry.
const userDataName = "user-data"

// mountCidata locates and mounts a cidata disk, returning the mount
// point and a cleanup func to unmount + rmdir. Implemented per-OS via
// build tags ; the stub below kicks in on platforms with no mount
// implementation so the package still compiles (and its direct-read
// path stays testable) everywhere.
var mountCidata = func() (string, func(), error) {
	return "", func() {}, errors.New("cidata disk mount not implemented on this platform")
}

// candidateDevices returns the device nodes to try, most likely first.
// Implemented per-OS via build tags : the naming conventions genuinely
// diverge (udev's by-label symlinks on Linux, bare disk nodes on the
// BSDs) and pretending otherwise would only hide the difference. What
// is now shared is everything downstream of the list.
//
// A variable rather than a function so tests can point the probe at
// ordinary files.
var candidateDevices = func() []string { return nil }

// maxStageBytes bounds how large an image the FAT32 opener will stage
// to a temporary file. go-filesystems/fat32 opens by path, so a FAT32
// candidate has to be copied out first ; at first boot, on a guest
// whose /tmp is frequently a small tmpfs, an unbounded copy is not
// acceptable. 256 MiB is far above any real cidata seed (cloud-init's
// are single-digit MiB, and FAT32's own floor is ~33 MiB) and far below
// anything that would fill a boot-time tmpfs. Above the cap the
// candidate is skipped, not read partially.
const maxStageBytes = 256 << 20

func init() {
	// iso9660 reads straight from an io.ReaderAt, so its opener is a
	// direct adapter — no staging, no temp file, no write handle.
	detect.Register(detect.ISO9660, func(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
		return iso9660.Open(r, size)
	})
	// FAT32 must be staged (the driver is path-based and opens O_RDWR).
	// detect/fat32reg does exactly that ; we call it through our own
	// tighter size bound instead of blank-importing it, because its own
	// 8 GiB ceiling is far too generous for a boot path. Register is
	// idempotent and last-wins, so this replaces fat32reg's own init
	// registration deterministically.
	detect.Register(detect.FAT32, func(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
		if size < 0 || size > maxStageBytes {
			return nil, fmt.Errorf("fat32 image size %d outside the %d-byte staging bound", size, int64(maxStageBytes))
		}
		return fat32reg.Open(r, size)
	})
}

// readCidataFile opens dev read-only, identifies its filesystem and
// reads name out of it. It is the whole of the new datapath and is
// deliberately free of build tags : one implementation for Linux and
// every BSD, exercisable on any host against an ordinary file.
func readCidataFile(dev, name string) ([]byte, detect.Type, error) {
	f, err := os.Open(dev)
	if err != nil {
		return nil, detect.Unknown, err
	}
	defer f.Close()

	fs, typ, err := detect.Open(f, deviceSize(f))
	if err != nil {
		return nil, typ, err
	}
	defer fs.Close()

	data, err := readNamed(fs, name)
	if err != nil {
		return nil, typ, err
	}
	return data, typ, nil
}

// sizeProbe is the slice of *os.File deviceSize needs. It exists so a
// test can present the one shape a test host cannot create: a
// non-regular file whose length only a seek will reveal, which is
// exactly what a Linux block device is.
type sizeProbe interface {
	Stat() (os.FileInfo, error)
	Seek(offset int64, whence int) (int64, error)
}

// deviceSize reports the byte length of f, or -1 when it cannot be
// determined. A regular file answers through Stat ; a Linux block
// device reports 0 there, so we seek to the end, which the block layer
// answers without an ioctl (and so without per-OS code). The offset is
// restored afterwards, because the caller goes on to read through the
// same descriptor.
//
// Drivers accept -1 and fall back to their own bounded-allocation
// ceiling, so an unknown size costs capability (FAT32 staging needs a
// real length), never safety.
func deviceSize(f sizeProbe) int64 {
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		return fi.Size()
	}
	n, err := f.Seek(0, io.SeekEnd)
	if err != nil || n <= 0 {
		return -1
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return -1
	}
	return n
}

// readNamed reads name from fs, tolerating the name manglings the two
// on-disk formats apply.
//
// A cidata ISO minted the usual way (cloud-localds, i.e. genisoimage
// -joliet -rock) stores "user-data" verbatim in its Rock Ridge tree, so
// the exact path is tried first and is what real seeds hit. An ISO
// minted without those options is restricted to ECMA-119 level 1 —
// eight upper-case characters from [A-Z0-9_], a dot, and a ";1" version
// suffix — so the same file is on disk as "USER_DAT". FAT stores an 8.3
// alias ("USER-D~1") beside the long name.
//
// So : exact path, then an exact-ish scan of the root directory
// (case-folded, version suffix ignored), then a last pass that undoes
// the level-1 mangling. The passes are ordered so a directory that does
// contain a plainly-named user-data can never be answered from a
// fuzzily-matched neighbour.
func readNamed(fs filesystem.Filesystem, name string) ([]byte, error) {
	if data, err := fs.ReadFile("/" + name); err == nil {
		return data, nil
	}
	entries, err := fs.ListDir("/")
	if err != nil {
		return nil, fmt.Errorf("list root: %w", err)
	}
	for _, match := range []func(got, want string) bool{exactName, mangledName} {
		for _, e := range entries {
			if match(e.Name(), name) {
				return fs.ReadFile("/" + e.Name())
			}
		}
	}
	return nil, fmt.Errorf("%s not present", name)
}

// exactName reports a case-insensitive match once an ISO 9660 version
// suffix (";1") and its trailing dot are discounted.
func exactName(got, want string) bool {
	return strings.EqualFold(trimISOSuffix(got), want)
}

// mangledName reports whether got is what ECMA-119 level 1 makes of
// want : every character outside [A-Z0-9_] replaced by "_", then
// truncated to eight. Both sides are normalised the same way, and a
// truncated match must still be at least minManglePrefix characters so
// an unrelated short name can never pass for the seed.
func mangledName(got, want string) bool {
	g, w := mangle(trimISOSuffix(got)), mangle(want)
	if g == w {
		return true
	}
	const minManglePrefix = 8
	return len(g) >= minManglePrefix && len(g) < len(w) && g == w[:len(g)]
}

// trimISOSuffix drops an ECMA-119 ";<version>" suffix and the trailing
// dot a level-1 name keeps when it has no extension.
func trimISOSuffix(s string) string {
	if i := strings.LastIndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

// mangle upper-cases s and replaces every character ECMA-119 level 1
// forbids in a file identifier with an underscore — the same
// substitution the mastering tool made on the way in.
func mangle(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - ('a' - 'A')
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, s)
}
