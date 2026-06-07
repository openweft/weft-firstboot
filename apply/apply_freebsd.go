//go:build freebsd

package apply

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// freebsdSystem is the FreeBSD-flavoured System. rc.conf edits go
// through sysrc(8) (the canonical rc.conf editor) ; user/group mutations
// go through pw(8) ; everything else is plain syscalls.
type freebsdSystem struct {
	log *slog.Logger
}

// NewFreeBSDSystem returns the FreeBSD System implementation.
func NewFreeBSDSystem(log *slog.Logger) System {
	if log == nil {
		log = slog.Default()
	}
	return &freebsdSystem{log: log}
}

// osNewSystem is the per-OS hook the factory in factory.go dispatches
// to ; on freebsd it just delegates to NewFreeBSDSystem.
func osNewSystem(log *slog.Logger) System { return NewFreeBSDSystem(log) }

// Hostname reads the live kernel value via /bin/hostname ; rc.conf may
// lag during first-boot so we trust the kernel, not the persisted file.
func (s *freebsdSystem) Hostname() (string, error) {
	out, err := exec.Command("/bin/hostname").Output()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// SetHostname persists via sysrc (idempotent by design : it rewrites the
// hostname= line in /etc/rc.conf) and applies live via /bin/hostname.
func (s *freebsdSystem) SetHostname(name string) error {
	if err := run("/usr/sbin/sysrc", fmt.Sprintf("hostname=%s", name)); err != nil {
		return fmt.Errorf("sysrc hostname: %w", err)
	}
	if err := run("/bin/hostname", name); err != nil {
		return fmt.Errorf("hostname %s: %w", name, err)
	}
	return nil
}

// UserExists greps /etc/passwd for a literal "name:" line prefix ;
// avoids pulling in getpwnam(3) which would require cgo.
func (s *freebsdSystem) UserExists(name string) (bool, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false, fmt.Errorf("read /etc/passwd: %w", err)
	}
	prefix := []byte(name + ":")
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// CreateUser uses pw(8). Missing groups are created first ; the
// password hash is fed on stdin to `pw usermod -H 0` (pre-hashed mode).
// Empty hash → locked account.
func (s *freebsdSystem) CreateUser(name, shell, passwordHash string, extraGroups []string) error {
	if shell == "" {
		shell = "/bin/sh"
	}
	if err := s.ensureGroups(extraGroups); err != nil {
		return err
	}
	args := []string{"useradd", name, "-m", "-s", shell}
	if len(extraGroups) > 0 {
		args = append(args, "-G", strings.Join(extraGroups, ","))
	}
	if err := run("/usr/sbin/pw", args...); err != nil {
		return fmt.Errorf("pw useradd %s: %w", name, err)
	}
	if passwordHash == "" {
		if err := run("/usr/sbin/pw", "lock", name); err != nil {
			return fmt.Errorf("pw lock %s: %w", name, err)
		}
		return nil
	}
	cmd := exec.Command("/usr/sbin/pw", "usermod", name, "-H", "0")
	cmd.Stdin = strings.NewReader(passwordHash)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pw usermod -H %s: %w: %s", name, err, out)
	}
	return nil
}

// AddUserToGroups appends to existing membership : pw usermod -G is a
// REPLACE op, so we union with the current set from id(1) first.
func (s *freebsdSystem) AddUserToGroups(name string, extraGroups []string) error {
	if len(extraGroups) == 0 {
		s.log.Debug("AddUserToGroups: no groups requested", "user", name)
		return nil
	}
	if err := s.ensureGroups(extraGroups); err != nil {
		return err
	}
	out, err := exec.Command("/usr/bin/id", "-Gn", name).Output()
	if err != nil {
		return fmt.Errorf("id -Gn %s: %w", name, err)
	}
	current := strings.Fields(strings.TrimSpace(string(out)))
	union := append([]string(nil), current...)
	for _, g := range extraGroups {
		if !contains(union, g) {
			union = append(union, g)
		}
	}
	if len(union) == len(current) {
		s.log.Debug("AddUserToGroups: no diff", "user", name, "groups", current)
		return nil
	}
	if err := run("/usr/sbin/pw", "usermod", name, "-G", strings.Join(union, ",")); err != nil {
		return fmt.Errorf("pw usermod -G %s: %w", name, err)
	}
	return nil
}

// ensureGroups creates groups one by one ; pw groupadd returns 65
// (EX_DATAERR) when the group already exists, which we treat as success.
func (s *freebsdSystem) ensureGroups(groups []string) error {
	for _, g := range groups {
		if g == "" {
			continue
		}
		cmd := exec.Command("/usr/sbin/pw", "groupadd", g)
		out, err := cmd.CombinedOutput()
		if err == nil {
			continue
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 65 {
			s.log.Debug("group already exists", "group", g)
			continue
		}
		return fmt.Errorf("pw groupadd %s: %w: %s", g, err, out)
	}
	return nil
}

// AddAuthorizedKey appends key to ~user/.ssh/authorized_keys, creating
// the dir+file with the FreeBSD-canonical perms and the user's uid:gid.
func (s *freebsdSystem) AddAuthorizedKey(username, key string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("gid %q: %w", u.Gid, err)
	}
	sshDir := filepath.Join(u.HomeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", sshDir, err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	trimmed := strings.TrimRight(key, "\n")
	existing, err := os.ReadFile(akPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", akPath, err)
	}
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == trimmed {
			s.log.Debug("ssh key already present", "user", username)
			return nil
		}
	}
	buf := append([]byte(nil), existing...)
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	buf = append(buf, []byte(trimmed+"\n")...)
	if err := os.WriteFile(akPath, buf, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", akPath, err)
	}
	if err := os.Chmod(akPath, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", akPath, err)
	}
	if err := os.Chown(akPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", akPath, err)
	}
	return nil
}

// WriteFile is atomic via tempfile-in-same-dir + rename. Diff-skip
// keeps re-runs no-op when content/mode/owner all already match.
func (s *freebsdSystem) WriteFile(path, content, mode, owner, group string) error {
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "wheel"
	}
	m, err := parseMode(mode)
	if err != nil {
		return err
	}
	uid, gid, err := resolveOwner(owner, group)
	if err != nil {
		return err
	}
	if same, err := fileMatches(path, content, m, uid, gid); err != nil {
		return err
	} else if same {
		s.log.Debug("WriteFile: no diff", "path", path)
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".firstboot-*")
	if err != nil {
		return fmt.Errorf("tempfile in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(m); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Chown(tmpPath, uid, gid); err != nil {
		cleanup()
		return fmt.Errorf("chown %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// PackageInstall calls `pkg install -y` (auto-yes). pkg(8) bootstraps
// itself on first invocation (downloads /usr/local/sbin/pkg-static)
// when only the stub is present ; -y also accepts that prompt.
// Already-installed packages are skipped silently by pkg.
func (s *freebsdSystem) PackageInstall(pkgs []string) error {
	if len(pkgs) == 0 {
		return nil
	}
	s.log.Info("package install", "pkgs", pkgs)
	argv := append([]string{"install", "-y"}, pkgs...)
	c := exec.Command("/usr/sbin/pkg", argv...)
	// ASSUME_ALWAYS_YES covers the pkg-bootstrap prompt the first time.
	c.Env = append(os.Environ(), "ASSUME_ALWAYS_YES=YES")
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pkg install %v: %w: %s", pkgs, err, bytes.TrimSpace(out))
	}
	return nil
}

// RunShell runs through /bin/sh -c so users can pipe / && / redirect as
// in their cloud-init manifest.
func (s *freebsdSystem) RunShell(cmd string) error {
	c := exec.Command("/bin/sh", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		s.log.Debug("RunShell failed", "cmd", cmd, "err", err, "out", string(out))
		return fmt.Errorf("/bin/sh -c %q: %w: %s", cmd, err, out)
	}
	s.log.Debug("RunShell ok", "cmd", cmd)
	return nil
}

// parseMode accepts "" (→0644), "0644", "644", "0o644".
func parseMode(mode string) (fs.FileMode, error) {
	if mode == "" {
		return 0o644, nil
	}
	m := strings.TrimPrefix(mode, "0o")
	v, err := strconv.ParseUint(m, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parse mode %q: %w", mode, err)
	}
	return fs.FileMode(v), nil
}

// resolveOwner translates name → uid/gid via user.Lookup ; pure-Go
// (no cgo) backed by /etc/passwd + /etc/group parsing.
func resolveOwner(owner, group string) (int, int, error) {
	u, err := user.Lookup(owner)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %s: %w", owner, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %s: %w", group, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid %q: %w", g.Gid, err)
	}
	return uid, gid, nil
}

// fileMatches returns true if path already holds the exact target
// content+mode+uid+gid (the WriteFile idempotency check).
func fileMatches(path, content string, mode fs.FileMode, uid, gid int) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode().Perm() != mode.Perm() {
		return false, nil
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if string(cur) != content {
		return false, nil
	}
	// Owner check uses syscall stat (cross-Unix safe via the public
	// Sys() escape hatch). Mismatch → rewrite (cheap).
	return statOwnerMatches(st, uid, gid), nil
}

// statOwnerMatches inspects the syscall.Stat_t under the FileInfo to
// compare uid/gid ; fs.FileInfo intentionally hides those.
func statOwnerMatches(st fs.FileInfo, uid, gid int) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(sys.Uid) == uid && int(sys.Gid) == gid
}

// run is a thin wrapper that funnels CombinedOutput into the error so
// the caller sees what pw/sysrc actually said.
func run(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
