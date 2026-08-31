package datasource

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-filesystems/detect"
	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/iso9660"
)

// The seed payload every image in this file carries. Real HCL, so the
// whole fromDisk path (read -> Parse -> Config) is exercised, not just
// the byte read.
const seedUserData = `hostname = "vmd-proof"

user "openbsd" {
  ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIProof proof@host"]
  groups              = ["operator", "wheel"]
  doas                = true
  shell               = "/bin/ksh"
}

runcmd = [
  "rcctl enable ntpd",
]
`

const seedMetaData = "instance-id: iid-proof-0001\nlocal-hostname: vmd-proof\n"

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// withCandidates points the probe at the given paths for one test and
// restores the real enumeration afterwards.
func withCandidates(t *testing.T, paths ...string) {
	t.Helper()
	prev := candidateDevices
	candidateDevices = func() []string { return paths }
	t.Cleanup(func() { candidateDevices = prev })
}

// withMount replaces the mount fallback for one test.
func withMount(t *testing.T, f func() (string, func(), error)) {
	t.Helper()
	prev := mountCidata
	mountCidata = f
	t.Cleanup(func() { mountCidata = prev })
}

// buildISO writes a real ISO 9660 image holding the named files. The
// go-filesystems Builder emits a plain ECMA-119 tree with no Rock Ridge
// and no Joliet, so "user-data" is stored 8.3-mangled — which is
// exactly the mangling readNamed has to survive, and the shape an ISO
// minted without -rock -joliet has in the field.
func buildISO(t *testing.T, files map[string]string) string {
	t.Helper()
	b := iso9660.NewBuilder("CIDATA")
	for name, data := range files {
		if err := b.AddFile("/"+name, []byte(data)); err != nil {
			t.Fatalf("iso AddFile %s: %v", name, err)
		}
	}
	path := filepath.Join(t.TempDir(), "cidata.iso")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WriteTo(f); err != nil {
		t.Fatalf("iso WriteTo: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// fat32MinSize is the smallest image go-filesystems/fat32 will format.
const fat32MinSize = 4 << 20

// buildFAT32 writes a real FAT32 image holding the named files.
func buildFAT32(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cidata.img")
	fs, err := fat32.Format(path, fat32MinSize, fat32.FormatConfig{Label: "CIDATA"})
	if err != nil {
		t.Fatalf("fat32 Format: %v", err)
	}
	for name, data := range files {
		if err := fs.WriteFile("/"+name, []byte(data), 0o644); err != nil {
			t.Fatalf("fat32 WriteFile %s: %v", name, err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("fat32 Close: %v", err)
	}
	return path
}

func seedFiles() map[string]string {
	return map[string]string{"user-data": seedUserData, "meta-data": seedMetaData}
}

// --- equivalence : the bytes a mount used to hand us, byte for byte ---

// TestReadCidataFileBytesAreExact reads both file names out of both
// filesystem flavours and asserts the sha256 of every read equals the
// sha256 of what went in. "Same length" or "parses fine" would both
// pass while silently truncating or re-encoding; the digest will not.
func TestReadCidataFileBytesAreExact(t *testing.T) {
	images := map[string]struct {
		path string
		typ  detect.Type
	}{
		"iso9660": {buildISO(t, seedFiles()), detect.ISO9660},
		"fat32":   {buildFAT32(t, seedFiles()), detect.FAT32},
	}
	want := map[string]string{
		"user-data": sum([]byte(seedUserData)),
		"meta-data": sum([]byte(seedMetaData)),
	}
	for flavour, img := range images {
		for name, wantSum := range want {
			got, typ, err := readCidataFile(img.path, name)
			if err != nil {
				t.Fatalf("%s: readCidataFile %s: %v", flavour, name, err)
			}
			if typ != img.typ {
				t.Errorf("%s: detected type = %q, want %q", flavour, typ, img.typ)
			}
			if gotSum := sum(got); gotSum != wantSum {
				t.Errorf("%s/%s: sha256 = %s, want %s (%d bytes read)", flavour, name, gotSum, wantSum, len(got))
			}
		}
	}
}

// TestFromDiskDirectISO9660 walks the whole probe on a real ISO.
func TestFromDiskDirectISO9660(t *testing.T) {
	withCandidates(t, buildISO(t, seedFiles()))
	src, err := fromDisk()
	if err != nil {
		t.Fatalf("fromDisk: %v", err)
	}
	if sum(src.Raw) != sum([]byte(seedUserData)) {
		t.Errorf("Raw sha256 = %s, want %s", sum(src.Raw), sum([]byte(seedUserData)))
	}
	if src.Config.Hostname != "vmd-proof" {
		t.Errorf("Hostname = %q, want vmd-proof", src.Config.Hostname)
	}
	if !strings.Contains(src.Origin, "iso9660, direct") {
		t.Errorf("Origin = %q, should name the driver and the direct path", src.Origin)
	}
}

// TestFromDiskDirectFAT32 does the same for a vfat seed. Under the old
// code this shape reached the kernel's vfat/msdos driver; it must still
// be found, now without mounting.
func TestFromDiskDirectFAT32(t *testing.T) {
	withCandidates(t, buildFAT32(t, seedFiles()))
	src, err := fromDisk()
	if err != nil {
		t.Fatalf("fromDisk: %v", err)
	}
	if sum(src.Raw) != sum([]byte(seedUserData)) {
		t.Errorf("Raw sha256 = %s, want %s", sum(src.Raw), sum([]byte(seedUserData)))
	}
	if !strings.Contains(src.Origin, "fat32, direct") {
		t.Errorf("Origin = %q, should name the driver and the direct path", src.Origin)
	}
}

// --- the failure modes that make this class of code misbehave ---

// TestFromDiskSkipsAbsentDevice : a candidate that does not exist must
// not end the walk. This is the common case on every real guest, where
// most of the candidate list is absent.
func TestFromDiskSkipsAbsentDevice(t *testing.T) {
	good := buildISO(t, seedFiles())
	withCandidates(t, filepath.Join(t.TempDir(), "definitely-absent"), good)
	if _, err := fromDisk(); err != nil {
		t.Fatalf("absent candidate should be skipped, got %v", err)
	}
}

// TestFromDiskSkipsUnreadableDevice : a device we may not open (the
// unprivileged case this change is all about) must be skipped, not
// fatal.
func TestFromDiskSkipsUnreadableDevice(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root : mode 0000 is readable, the case cannot be built")
	}
	locked := filepath.Join(t.TempDir(), "locked.img")
	if err := os.WriteFile(locked, make([]byte, 4096), 0o000); err != nil {
		t.Fatal(err)
	}
	good := buildISO(t, seedFiles())
	withCandidates(t, locked, good)
	src, err := fromDisk()
	if err != nil {
		t.Fatalf("unreadable candidate should be skipped, got %v", err)
	}
	if !strings.Contains(src.Origin, good) {
		t.Errorf("Origin = %q, want the readable candidate %q", src.Origin, good)
	}
}

// TestFromDiskSkipsFilesystemWithoutUserData : a perfectly valid,
// readable filesystem that simply is not the seed must not stop the
// walk. Getting this wrong is how a probe "finds" the wrong disk and
// then reports no datasource at all.
func TestFromDiskSkipsFilesystemWithoutUserData(t *testing.T) {
	decoy := buildISO(t, map[string]string{"meta-data": seedMetaData, "readme": "not the seed"})
	decoyFAT := buildFAT32(t, map[string]string{"other-file": "not the seed"})
	good := buildISO(t, seedFiles())
	withCandidates(t, decoy, decoyFAT, good)
	src, err := fromDisk()
	if err != nil {
		t.Fatalf("fromDisk: %v", err)
	}
	if !strings.Contains(src.Origin, good) {
		t.Errorf("Origin = %q, want the seed image %q", src.Origin, good)
	}
	if sum(src.Raw) != sum([]byte(seedUserData)) {
		t.Error("read the decoy's bytes instead of the seed's")
	}
}

// TestFromDiskTruncatedImage : an image cut short must never panic and
// must never hand back wrong bytes. Every 512-byte boundary of a real
// ISO is tried, which cuts inside the system area, the volume
// descriptor, the path table, the directory extent and the file data in
// turn. A truncation past the end of the seed's own extent legitimately
// still reads — the assertion is therefore "ErrNotFound, or the exact
// bytes", never "something plausible".
func TestFromDiskTruncatedImage(t *testing.T) {
	full, err := os.ReadFile(buildISO(t, seedFiles()))
	if err != nil {
		t.Fatal(err)
	}
	want := sum([]byte(seedUserData))
	dir := t.TempDir()
	var readable int
	for n := 0; n <= len(full); n += 512 {
		path := filepath.Join(dir, "trunc.img")
		if err := os.WriteFile(path, full[:n], 0o644); err != nil {
			t.Fatal(err)
		}
		withCandidates(t, path)
		src, err := fromDisk()
		switch {
		case errors.Is(err, ErrNotFound):
			// Cut too deep to serve the seed : the honest answer.
		case err != nil:
			t.Errorf("truncated at %d bytes: unexpected error class %v", n, err)
		case sum(src.Raw) != want:
			t.Errorf("truncated at %d bytes: served %d wrong bytes (sha256 %s)", n, len(src.Raw), sum(src.Raw))
		default:
			readable++
		}
	}
	if readable == 0 {
		t.Error("no truncation point served the seed ; the test is not exercising the success side")
	}
	// The full image must of course be readable.
	withCandidates(t, buildISO(t, seedFiles()))
	if _, err := fromDisk(); err != nil {
		t.Errorf("untruncated image: %v", err)
	}
}

// TestFromDiskCorruptImage : random bytes, and the nastier case of an
// image that carries a valid magic signature but nothing behind it, so
// detection succeeds and the driver is handed garbage.
func TestFromDiskCorruptImage(t *testing.T) {
	dir := t.TempDir()

	noise := make([]byte, 128<<10)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	noisePath := filepath.Join(dir, "noise.img")
	if err := os.WriteFile(noisePath, noise, 0o644); err != nil {
		t.Fatal(err)
	}

	// ISO 9660 magic at 0x8001, everything else zero.
	fakeISO := make([]byte, 64<<10)
	copy(fakeISO[0x8001:], []byte("CD001"))
	fakeISOPath := filepath.Join(dir, "fake-iso.img")
	if err := os.WriteFile(fakeISOPath, fakeISO, 0o644); err != nil {
		t.Fatal(err)
	}

	// FAT32 boot signature + type label, nothing else.
	fakeFAT := make([]byte, 64<<10)
	copy(fakeFAT[0x52:], []byte("FAT32   "))
	fakeFAT[510], fakeFAT[511] = 0x55, 0xAA
	fakeFATPath := filepath.Join(dir, "fake-fat.img")
	if err := os.WriteFile(fakeFATPath, fakeFAT, 0o644); err != nil {
		t.Fatal(err)
	}

	// A file too small to carry any signature at all.
	tiny := filepath.Join(dir, "tiny.img")
	if err := os.WriteFile(tiny, []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}

	withCandidates(t, noisePath, fakeISOPath, fakeFATPath, tiny)
	if _, err := fromDisk(); !errors.Is(err, ErrNotFound) {
		t.Errorf("corrupt candidates: err = %v, want ErrNotFound", err)
	}

	// And a corrupt disk ahead of the real one must not shadow it.
	good := buildISO(t, seedFiles())
	withCandidates(t, noisePath, fakeISOPath, fakeFATPath, tiny, good)
	src, err := fromDisk()
	if err != nil {
		t.Fatalf("corrupt candidates shadowed the seed: %v", err)
	}
	if sum(src.Raw) != sum([]byte(seedUserData)) {
		t.Error("did not read the seed")
	}
}

// TestFromDiskOversizeFAT32IsRefusedNotStaged : the staging bound has to
// bite before the copy, otherwise a large disk fills /tmp at boot.
func TestFromDiskOversizeFAT32IsRefusedNotStaged(t *testing.T) {
	path := buildFAT32(t, seedFiles())
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse-extend past the bound. The boot sector is untouched, so
	// detection still says fat32 ; only the size check can refuse it.
	if err := f.Truncate(maxStageBytes + 1); err != nil {
		f.Close()
		t.Skipf("cannot create a sparse oversize image here: %v", err)
	}
	f.Close()
	withCandidates(t, path)
	if _, err := fromDisk(); !errors.Is(err, ErrNotFound) {
		t.Errorf("oversize fat32: err = %v, want ErrNotFound", err)
	}
}

// TestFromDiskBadUserDataIsFatal : the seed was found but its payload
// does not parse. Falling through to the HTTP datasource here would
// apply somebody else's configuration, so this is deliberately a hard
// error rather than ErrNotFound.
func TestFromDiskBadUserDataIsFatal(t *testing.T) {
	withCandidates(t, buildISO(t, map[string]string{"user-data": "hostname = = ="}))
	_, err := fromDisk()
	if err == nil {
		t.Fatal("unparseable user-data should be an error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, should not be ErrNotFound (that would fall through to HTTP)", err)
	}
}

// --- the fallback, and the fact that it says so ---

// TestFromDiskFallsBackToMountAndSaysSo : when no candidate can be read
// directly, the mount path runs — and Origin records that it did. A
// fallback nobody can see in the log is a regression nobody can find.
func TestFromDiskFallsBackToMountAndSaysSo(t *testing.T) {
	withCandidates(t) // nothing readable directly
	mnt := t.TempDir()
	if err := os.WriteFile(filepath.Join(mnt, "user-data"), []byte(seedUserData), 0o644); err != nil {
		t.Fatal(err)
	}
	var cleaned bool
	withMount(t, func() (string, func(), error) {
		return mnt, func() { cleaned = true }, nil
	})
	src, err := fromDisk()
	if err != nil {
		t.Fatalf("fromDisk: %v", err)
	}
	if !strings.Contains(src.Origin, "mount fallback") {
		t.Errorf("Origin = %q, must say the fallback served", src.Origin)
	}
	if sum(src.Raw) != sum([]byte(seedUserData)) {
		t.Error("fallback returned different bytes")
	}
	if !cleaned {
		t.Error("mount cleanup was not run")
	}
}

// TestFromDiskDirectWinsOverMount : the mount must not run at all when
// the direct read succeeds. That is the whole point of the change.
func TestFromDiskDirectWinsOverMount(t *testing.T) {
	withCandidates(t, buildISO(t, seedFiles()))
	var mounted bool
	withMount(t, func() (string, func(), error) {
		mounted = true
		return "", func() {}, errors.New("should not be reached")
	})
	if _, err := fromDisk(); err != nil {
		t.Fatalf("fromDisk: %v", err)
	}
	if mounted {
		t.Error("mount fallback ran even though the direct read succeeded")
	}
}

// TestFromDiskMountFallbackFailures covers the fallback's own error
// paths : no mountable device, and a mount that yields no user-data.
func TestFromDiskMountFallbackFailures(t *testing.T) {
	withCandidates(t)

	withMount(t, func() (string, func(), error) {
		return "", func() {}, errors.New("nothing to mount")
	})
	if _, err := fromDisk(); !errors.Is(err, ErrNotFound) {
		t.Errorf("no mountable device: err = %v, want ErrNotFound", err)
	}

	empty := t.TempDir()
	withMount(t, func() (string, func(), error) { return empty, func() {}, nil })
	if _, err := fromDisk(); !errors.Is(err, ErrNotFound) {
		t.Errorf("mount without user-data: err = %v, want ErrNotFound", err)
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "user-data"), []byte("hostname = = ="), 0o644); err != nil {
		t.Fatal(err)
	}
	withMount(t, func() (string, func(), error) { return bad, func() {}, nil })
	if _, err := fromDisk(); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("mount with unparseable user-data: err = %v, want a hard error", err)
	}
}

// TestDefaultMountStubIsNotFound : on a platform with no mount
// implementation the fallback degrades to ErrNotFound rather than
// blowing up the whole discovery chain.
func TestDefaultMountStubIsNotFound(t *testing.T) {
	withCandidates(t)
	withMount(t, func() (string, func(), error) {
		return "", func() {}, errors.New("cidata disk mount not implemented on this platform")
	})
	if _, err := fromDisk(); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// --- unit level ---

func TestNameMatching(t *testing.T) {
	cases := []struct {
		got   string
		exact bool
		mang  bool
	}{
		{"user-data", true, true},   // Rock Ridge / FAT long name
		{"USER-DATA", true, true},   // case-folded
		{"user-data;1", true, true}, // ISO version suffix
		{"USER-DATA;1", true, true},
		{"USER_DATA", false, true}, // level-1 character substitution
		{"USER_DAT", false, true},  // ... plus level-1 truncation
		{"USER_DAT.;1", false, true},
		{"USER-D~1", false, false}, // FAT 8.3 alias : not a prefix, no match
		{"meta-data", false, false},
		{"META_DAT", false, false},
		{"user", false, false},       // too short to be a safe prefix
		{"USER_DA", false, false},    // 7 chars : below the prefix floor
		{"user-datax", false, false}, // longer than the target
		{"", false, false},
	}
	for _, c := range cases {
		if got := exactName(c.got, "user-data"); got != c.exact {
			t.Errorf("exactName(%q) = %v, want %v", c.got, got, c.exact)
		}
		if got := mangledName(c.got, "user-data"); got != c.mang {
			t.Errorf("mangledName(%q) = %v, want %v", c.got, got, c.mang)
		}
	}
}

// TestReadNamedPrefersTheExactName : when a directory holds both a
// plainly-named user-data and something the fuzzy pass would also
// accept, the plain one must win.
func TestReadNamedPrefersTheExactName(t *testing.T) {
	// The go-filesystems ISO builder mangles everything, so build the
	// ambiguity by hand through a fake listing instead.
	fs := &listingFS{files: map[string]string{
		"USER_DAT":  "mangled neighbour",
		"user-data": seedUserData,
	}}
	got, err := readNamed(fs, userDataName)
	if err != nil {
		t.Fatalf("readNamed: %v", err)
	}
	if string(got) != seedUserData {
		t.Errorf("readNamed returned the fuzzy match, want the exact one")
	}
}

// TestReadNamedListDirFailure : a filesystem that opens but whose root
// cannot be listed is an error, not a panic.
func TestReadNamedListDirFailure(t *testing.T) {
	if _, err := readNamed(&listingFS{listErr: errors.New("bad root")}, userDataName); err == nil {
		t.Fatal("expected a list error")
	}
}

func TestDeviceSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, make([]byte, 1234), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := deviceSize(f); got != 1234 {
		t.Errorf("deviceSize(regular file) = %d, want 1234", got)
	}
	// After sizing, the caller must still be able to read from 0.
	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Errorf("ReadAt after deviceSize: %v", err)
	}

	// An empty file: Stat says 0 and the seek says 0, so the size is
	// unknown and the drivers fall back to their own ceiling.
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ef, err := os.Open(empty)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	if got := deviceSize(ef); got != -1 {
		t.Errorf("deviceSize(empty) = %d, want -1", got)
	}
}

// TestReadCidataFileMissingDevice is the plain not-there case.
func TestReadCidataFileMissingDevice(t *testing.T) {
	_, typ, err := readCidataFile(filepath.Join(t.TempDir(), "nope"), userDataName)
	if err == nil {
		t.Fatal("expected an error for a missing device")
	}
	if typ != detect.Unknown {
		t.Errorf("type = %q, want unknown", typ)
	}
}

// TestCandidateDevicesIsPlatformShaped is a smoke test on the real
// enumeration : whatever this platform returns must be absolute paths
// and free of duplicates, so a candidate is never probed twice.
func TestCandidateDevicesIsPlatformShaped(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range candidateDevices() {
		if !filepath.IsAbs(d) {
			t.Errorf("candidate %q is not an absolute path", d)
		}
		if seen[d] {
			t.Errorf("candidate %q listed twice", d)
		}
		seen[d] = true
	}
}

// listingFS is a minimal filesystem.Filesystem whose root listing and
// file bodies are fixed, used to build directory shapes the real image
// builders cannot produce. Only the read surface is implemented; the
// mutators are never reached from this package.
type listingFS struct {
	files   map[string]string
	listErr error
}

func (f *listingFS) Close() error { return nil }
func (f *listingFS) ReadFile(p string) ([]byte, error) {
	if v, ok := f.files[strings.TrimPrefix(p, "/")]; ok {
		return []byte(v), nil
	}
	return nil, os.ErrNotExist
}

func (f *listingFS) ListDir(string) ([]filesystem.DirEntry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	names := make([]string, 0, len(f.files))
	for n := range f.files {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]filesystem.DirEntry, 0, len(names))
	for i, n := range names {
		out = append(out, filesystem.NewDirEntry(uint64(i+1), n, 0))
	}
	return out, nil
}

func (f *listingFS) Stat(string) (filesystem.Stat, error)        { return nil, os.ErrNotExist }
func (f *listingFS) WriteFile(string, []byte, os.FileMode) error { return os.ErrPermission }
func (f *listingFS) ReadLink(string) (string, error)             { return "", os.ErrNotExist }
func (f *listingFS) MkDir(string, os.FileMode) error             { return os.ErrPermission }
func (f *listingFS) DeleteFile(string) error                     { return os.ErrPermission }
func (f *listingFS) DeleteDir(string) error                      { return os.ErrPermission }
func (f *listingFS) Rename(string, string) error                 { return os.ErrPermission }

// realCidataDirEnv names a directory of cidata images minted by the
// real mastering tools, plus the reference files they were built from.
const realCidataDirEnv = "WEFT_FIRSTBOOT_REAL_CIDATA_DIR"

// TestRealCidataImages is the equivalence proof against images the
// actual tools produced, rather than the pure-Go builders used above.
// It is skipped unless WEFT_FIRSTBOOT_REAL_CIDATA_DIR names a directory
// laid out as:
//
//	<dir>/seed/user-data      the reference bytes
//	<dir>/seed/meta-data
//	<dir>/*.iso, <dir>/*.img  images built from <dir>/seed by
//	                          xorriso / newfs_msdos / mkfs.vfat / ...
//
// The reference files are the same bytes an OS mount of those images
// hands back — verify that separately, once, with `mount` or `hdiutil
// attach` plus sha256sum. This test then asserts the pure-Go read
// returns those same digests, which closes "direct read == mount".
//
// It is env-gated rather than shipped with fixtures because a FAT32
// image cannot be smaller than ~33 MiB, which has no business in a
// repository.
func TestRealCidataImages(t *testing.T) {
	dir := os.Getenv(realCidataDirEnv)
	if dir == "" {
		t.Skipf("set %s to a directory of tool-minted cidata images to run this", realCidataDirEnv)
	}
	want := map[string]string{}
	for _, name := range []string{"user-data", "meta-data"} {
		ref, err := os.ReadFile(filepath.Join(dir, "seed", name))
		if err != nil {
			t.Fatalf("reference %s: %v", name, err)
		}
		want[name] = sum(ref)
		t.Logf("reference %-9s sha256 %s (%d bytes)", name, want[name], len(ref))
	}
	// An image listed in <dir>/unsupported.txt is one the pure-Go
	// drivers are known not to read, so the mount fallback is what
	// serves it in the field. The test asserts it really does still
	// fail : the day a driver grows the capability, this tells us to
	// delete the line rather than letting the gap rot undetected.
	unsupported := map[string]bool{}
	if raw, err := os.ReadFile(filepath.Join(dir, "unsupported.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				unsupported[line] = true
			}
		}
	}

	var images []string
	for _, pat := range []string{"*.iso", "*.img"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			t.Fatal(err)
		}
		images = append(images, m...)
	}
	if len(images) == 0 {
		t.Fatalf("no *.iso or *.img under %s", dir)
	}
	sort.Strings(images)
	for _, img := range images {
		base := filepath.Base(img)
		for name, wantSum := range want {
			got, typ, err := readCidataFile(img, name)
			if unsupported[base] {
				if err == nil {
					t.Errorf("%s/%s: listed in unsupported.txt but read fine now — delete the line and drop the mount fallback caveat", base, name)
				} else {
					t.Logf("%-8s %-20s %-9s UNSUPPORTED (mount fallback territory): %v", typ, base, name, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: read %s: %v", base, name, err)
				continue
			}
			gotSum := sum(got)
			status := "MATCH"
			if gotSum != wantSum {
				status = "MISMATCH"
				t.Errorf("%s/%s: sha256 %s, want %s", base, name, gotSum, wantSum)
			}
			t.Logf("%-8s %-20s %-9s %-7s sha256 %s (%d bytes)", typ, base, name, status, gotSum, len(got))
		}
	}
}

// fakeProbe presents the shape a test host cannot create: a
// non-regular file whose length only a seek reveals — a Linux block
// device, in other words.
type fakeProbe struct {
	mode     os.FileMode
	statSize int64
	statErr  error
	end      int64
	seekErr  error
	rewind   error
	seeks    int
}

func (p *fakeProbe) Stat() (os.FileInfo, error) {
	if p.statErr != nil {
		return nil, p.statErr
	}
	return fakeInfo{mode: p.mode, size: p.statSize}, nil
}

func (p *fakeProbe) Seek(_ int64, whence int) (int64, error) {
	p.seeks++
	if whence == io.SeekEnd {
		return p.end, p.seekErr
	}
	return 0, p.rewind
}

type fakeInfo struct {
	mode os.FileMode
	size int64
}

func (i fakeInfo) Name() string       { return "fake" }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() os.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

// TestDeviceSizeBlockDeviceShape covers the branch no test host can
// reach with a real file: Stat reports a device of length 0, and only
// the end-seek knows how big it is.
func TestDeviceSizeBlockDeviceShape(t *testing.T) {
	cases := []struct {
		name  string
		probe *fakeProbe
		want  int64
	}{
		{"block device : seek answers", &fakeProbe{mode: os.ModeDevice, statSize: 0, end: 40 << 20}, 40 << 20},
		{"stat fails, seek answers", &fakeProbe{statErr: errors.New("no stat"), end: 4096}, 4096},
		{"seek fails", &fakeProbe{mode: os.ModeDevice, seekErr: errors.New("ESPIPE")}, -1},
		{"seek says zero", &fakeProbe{mode: os.ModeDevice, end: 0}, -1},
		{"rewind fails", &fakeProbe{mode: os.ModeDevice, end: 4096, rewind: errors.New("ESPIPE")}, -1},
		{"regular but empty", &fakeProbe{mode: 0, statSize: 0, end: 0}, -1},
	}
	for _, c := range cases {
		if got := deviceSize(c.probe); got != c.want {
			t.Errorf("%s: deviceSize = %d, want %d", c.name, got, c.want)
		}
	}
	// A regular file must be answered by Stat alone : no seek at all,
	// so the caller's read offset is never disturbed.
	p := &fakeProbe{mode: 0, statSize: 1234, end: 9999}
	if got := deviceSize(p); got != 1234 {
		t.Errorf("regular file: deviceSize = %d, want 1234", got)
	}
	if p.seeks != 0 {
		t.Errorf("regular file: %d seeks issued, want 0", p.seeks)
	}
}
