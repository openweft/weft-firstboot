//go:build linux

package apply

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// linuxSystem implements System against a real Linux host. It shells
// out to coreutils (useradd, usermod, groupadd, chpasswd, passwd) for
// the bits we don't want to re-implement against /etc/shadow ourselves,
// but reads /etc/passwd directly so probes work in initramfs contexts
// where NSS modules may not yet be configured.
type linuxSystem struct {
	log *slog.Logger
}

// NewLinuxSystem returns a System wired against the live Linux host.
func NewLinuxSystem(log *slog.Logger) System {
	if log == nil {
		log = slog.Default()
	}
	return &linuxSystem{log: log}
}

// osNewSystem is the per-OS hook dispatched by the factory in
// factory.go ; on linux it just delegates to NewLinuxSystem.
func osNewSystem(log *slog.Logger) System { return NewLinuxSystem(log) }

// Hostname asks the kernel directly (unix.Gethostname) rather than
// reading /etc/hostname, so the result reflects the running state
// even if /etc/hostname was edited but not yet applied.
func (s *linuxSystem) Hostname() (string, error) {
	return os.Hostname()
}

// SetHostname writes /etc/hostname AND calls sethostname(2) so both
// the durable config and the running kernel converge. If /etc/hostname
// already matches AND the kernel agrees, we short-circuit.
func (s *linuxSystem) SetHostname(name string) error {
	current, _ := os.Hostname()
	existing, _ := os.ReadFile("/etc/hostname")
	if current == name && strings.TrimSpace(string(existing)) == name {
		s.log.Debug("hostname already converged", "name", name)
		return nil
	}
	if err := atomicWrite("/etc/hostname", []byte(name+"\n"), 0644); err != nil {
		return fmt.Errorf("write /etc/hostname: %w", err)
	}
	// Prefer the syscall (no PATH dependency, works in initramfs) ;
	// fall back to /bin/hostname for environments where the caller
	// lacks CAP_SYS_ADMIN but has a setuid wrapper.
	if err := unix.Sethostname([]byte(name)); err != nil {
		s.log.Debug("sethostname syscall failed ; falling back to /bin/hostname", "err", err)
		if out, err2 := exec.Command("hostname", name).CombinedOutput(); err2 != nil {
			return fmt.Errorf("hostname %s: %w (%s)", name, err2, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// UserExists scans /etc/passwd line-by-line for "name:". Avoids
// shelling out to getent so this works in early-boot when NSS is
// not configured (initramfs, rescue mode).
func (s *linuxSystem) UserExists(name string) (bool, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false, fmt.Errorf("read /etc/passwd: %w", err)
	}
	prefix := name + ":"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// CreateUser runs useradd then either chpasswd -e (pre-hashed crypt(3))
// or passwd -l (lock) so an empty hash never leaves the account
// passwordless. Missing supplementary groups are created via
// `groupadd -f` first so useradd's -G doesn't fail on unknown names.
func (s *linuxSystem) CreateUser(name, shell, passwordHash string, extraGroups []string) error {
	if shell == "" {
		shell = "/bin/bash"
	}
	if err := ensureGroups(extraGroups); err != nil {
		return err
	}
	args := []string{"-m", "-s", shell}
	if len(extraGroups) > 0 {
		args = append(args, "-G", strings.Join(extraGroups, ","))
	}
	args = append(args, name)
	if out, err := exec.Command("/usr/sbin/useradd", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	if passwordHash != "" {
		// chpasswd -e expects "<name>:<hash>" on stdin and treats the
		// hash as already-crypt(3)-encoded (no double-hashing).
		cmd := exec.Command("chpasswd", "-e")
		cmd.Stdin = strings.NewReader(name + ":" + passwordHash + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("chpasswd %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// Lock the account so an empty hash never means "any password OK".
	if out, err := exec.Command("passwd", "-l", name).CombinedOutput(); err != nil {
		return fmt.Errorf("passwd -l %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// AddUserToGroups appends groups via `usermod -aG`. The -a is critical :
// without it usermod REPLACES the supplementary group set. Missing
// groups are pre-created so usermod doesn't blow up on unknown names.
func (s *linuxSystem) AddUserToGroups(name string, extraGroups []string) error {
	if len(extraGroups) == 0 {
		s.log.Debug("no groups to add ; no-op", "user", name)
		return nil
	}
	if err := ensureGroups(extraGroups); err != nil {
		return err
	}
	out, err := exec.Command("usermod", "-aG", strings.Join(extraGroups, ","), name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("usermod -aG %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// AddAuthorizedKey resolves $HOME from /etc/passwd (not os/user.Lookup,
// which may go through NSS), then ensures ~/.ssh/authorized_keys exists
// with 0700/0600 perms owned by the user. If the key is already a line
// in the file, we no-op rather than duplicate.
func (s *linuxSystem) AddAuthorizedKey(username, key string) error {
	home, uid, gid, err := lookupHomeAndIDs(username)
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", sshDir, err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	trimmed := strings.TrimSpace(key)
	existing, err := os.ReadFile(akPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", akPath, err)
	}
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == trimmed {
			s.log.Debug("ssh key already present ; no-op", "user", username)
			return nil
		}
	}
	// Append with a leading newline if the existing content doesn't
	// end on one, otherwise we'd glue two keys onto the same line.
	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.WriteString(trimmed)
	buf.WriteByte('\n')
	if err := atomicWrite(akPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("write %s: %w", akPath, err)
	}
	if err := os.Chown(akPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", akPath, err)
	}
	return nil
}

// WriteFile diffs current vs requested (content + mode + uid/gid)
// before touching the disk so a converged run does zero I/O. The
// write itself uses atomicWrite (tempfile + rename) so a crash mid-
// write never leaves a half-truncated file.
func (s *linuxSystem) WriteFile(path, content, mode, owner, group string) error {
	if mode == "" {
		mode = "0644"
	}
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	parsedMode, err := parseMode(mode)
	if err != nil {
		return fmt.Errorf("parse mode %q: %w", mode, err)
	}
	uid, err := lookupUID(owner)
	if err != nil {
		return fmt.Errorf("lookup owner %q: %w", owner, err)
	}
	gid, err := lookupGID(group)
	if err != nil {
		return fmt.Errorf("lookup group %q: %w", group, err)
	}

	if existing, err := os.ReadFile(path); err == nil {
		if st, err2 := os.Stat(path); err2 == nil {
			sameContent := string(existing) == content
			sameMode := st.Mode().Perm() == parsedMode.Perm()
			sameOwner := true
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				sameOwner = int(sys.Uid) == uid && int(sys.Gid) == gid
			}
			if sameContent && sameMode && sameOwner {
				s.log.Debug("file already converged ; no-op", "path", path)
				return nil
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", path, err)
	}
	if err := atomicWrite(path, []byte(content), parsedMode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// PackageInstall dispatches to whichever package manager is present.
// Order : apt-get (debian/ubuntu) → dnf (fedora/rocky/alma) → yum
// (rhel7/centos7) → zypper (suse) → apk (alpine) → pacman (arch).
// We don't refresh the repo cache (apt-get update) — that's the
// caller's runcmd job ; running it implicitly hides upstream outages
// behind weft-firstboot logs. Empty list → no-op.
func (s *linuxSystem) PackageInstall(pkgs []string) error {
	if len(pkgs) == 0 {
		return nil
	}
	type pm struct {
		probe string
		argv  []string
	}
	candidates := []pm{
		{"/usr/bin/apt-get", []string{"apt-get", "install", "-y", "--no-install-recommends"}},
		{"/usr/bin/dnf", []string{"dnf", "install", "-y"}},
		{"/usr/bin/yum", []string{"yum", "install", "-y"}},
		{"/usr/bin/zypper", []string{"zypper", "--non-interactive", "install"}},
		{"/sbin/apk", []string{"apk", "add", "--no-cache"}},
		{"/usr/bin/pacman", []string{"pacman", "-S", "--noconfirm"}},
	}
	for _, c := range candidates {
		if _, err := os.Stat(c.probe); err != nil {
			continue
		}
		argv := append(append([]string(nil), c.argv...), pkgs...)
		s.log.Info("package install", "manager", c.probe, "pkgs", pkgs)
		cmd := exec.Command(argv[0], argv[1:]...)
		// Most Linux pkg managers want non-interactive env hints.
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s install: %w (%s)", c.probe, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return fmt.Errorf("no supported package manager found (looked for apt-get / dnf / yum / zypper / apk / pacman)")
}

// RunShell executes `sh -c cmd` with stdout+stderr blended so the
// error we return on non-zero exit carries the full diagnostic
// (cloud-init runcmd failures are notoriously opaque without it).
func (s *linuxSystem) RunShell(cmd string) error {
	s.log.Debug("run shell", "cmd", cmd)
	c := exec.Command("sh", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sh -c %q: %w (%s)", cmd, err, strings.TrimSpace(string(out)))
	}
	s.log.Debug("shell ok", "cmd", cmd, "out", strings.TrimSpace(string(out)))
	return nil
}

// ---- helpers ----

// ensureGroups pre-creates any group named in gs via `groupadd -f`,
// which is a no-op if the group already exists. Called before useradd
// -G / usermod -aG so those commands don't fail on unknown groups.
func ensureGroups(gs []string) error {
	for _, g := range gs {
		if g == "" {
			continue
		}
		if out, err := exec.Command("groupadd", "-f", g).CombinedOutput(); err != nil {
			return fmt.Errorf("groupadd -f %s: %w (%s)", g, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// lookupHomeAndIDs reads /etc/passwd directly (NSS-free) to find the
// user's home + uid/gid. Needed in initramfs where os/user.Lookup may
// fail because NSS modules aren't loaded.
func lookupHomeAndIDs(username string) (home string, uid, gid int, err error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", 0, 0, fmt.Errorf("read /etc/passwd: %w", err)
	}
	prefix := username + ":"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		f := strings.Split(line, ":")
		if len(f) < 7 {
			return "", 0, 0, fmt.Errorf("malformed /etc/passwd line for %s", username)
		}
		uid64, perr := strconv.Atoi(f[2])
		if perr != nil {
			return "", 0, 0, fmt.Errorf("parse uid for %s: %w", username, perr)
		}
		gid64, perr := strconv.Atoi(f[3])
		if perr != nil {
			return "", 0, 0, fmt.Errorf("parse gid for %s: %w", username, perr)
		}
		return f[5], uid64, gid64, nil
	}
	return "", 0, 0, fmt.Errorf("user %s not found in /etc/passwd", username)
}

// lookupUID resolves a username to a uid via os/user, accepting a
// numeric string as a shortcut so callers can pass "0" instead of
// "root" when NSS isn't available.
func lookupUID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

// lookupGID mirrors lookupUID for groups.
func lookupGID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// parseMode parses an octal mode string ("0644", "644", "0o644").
func parseMode(mode string) (os.FileMode, error) {
	s := strings.TrimPrefix(strings.TrimPrefix(mode, "0o"), "0O")
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(n), nil
}

// atomicWrite writes data to a tempfile in the same directory then
// renames over the target. The rename is atomic on the same fs, so
// readers either see the old file or the new file -- never a torn
// half-write.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".weft-firstboot-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		// Best-effort cleanup if rename never happened.
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
