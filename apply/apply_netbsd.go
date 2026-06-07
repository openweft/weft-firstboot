//go:build netbsd

package apply

import (
	"bufio"
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

// netbsdSystem implements System for NetBSD. NetBSD ships no sysrc(8)
// equivalent ; /etc/rc.conf is hand-edited and that is the canonical
// flow (mentioned explicitly in rc.conf(5)).
type netbsdSystem struct {
	log *slog.Logger
}

// NewNetBSDSystem returns the NetBSD System implementation.
func NewNetBSDSystem(log *slog.Logger) System {
	return &netbsdSystem{log: log}
}

// osNewSystem is the build-tagged hook consumed by factory.go.
func osNewSystem(log *slog.Logger) System { return NewNetBSDSystem(log) }

const (
	netbsdRcConf       = "/etc/rc.conf"
	netbsdDefaultShell = "/bin/sh"
	netbsdDefaultOwner = "root"
	netbsdDefaultGroup = "wheel" // NetBSD root's primary group
	netbsdDefaultMode  = 0o644
)

// Hostname returns the kernel's live hostname (post any SetHostname).
func (s *netbsdSystem) Hostname() (string, error) {
	out, err := exec.Command("/bin/hostname").Output()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// SetHostname rewrites the hostname= line in /etc/rc.conf (idempotent
// in-place edit ; NetBSD has no sysrc(8)) then applies it live.
func (s *netbsdSystem) SetHostname(name string) error {
	if err := rewriteRcConfHostname(name); err != nil {
		return fmt.Errorf("update %s: %w", netbsdRcConf, err)
	}
	if out, err := exec.Command("/bin/hostname", name).CombinedOutput(); err != nil {
		return fmt.Errorf("hostname %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// rewriteRcConfHostname does an in-place hostname= line swap, appending
// the line if missing. Atomic via tempfile+rename in /etc.
func rewriteRcConfHostname(name string) error {
	wanted := fmt.Sprintf("hostname=%s", name)

	existing, err := os.ReadFile(netbsdRcConf)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	var out bytes.Buffer
	replaced := false
	scanner := bufio.NewScanner(bytes.NewReader(existing))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "hostname=") {
			if line == wanted {
				// Already correct ; preserve byte-for-byte.
				out.WriteString(line)
				out.WriteByte('\n')
			} else {
				out.WriteString(wanted)
				out.WriteByte('\n')
			}
			replaced = true
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !replaced {
		out.WriteString(wanted)
		out.WriteByte('\n')
	}

	// No-op if content matches what's already on disk.
	if bytes.Equal(existing, out.Bytes()) {
		return nil
	}
	return atomicWrite(netbsdRcConf, out.Bytes(), 0o644, -1, -1)
}

// UserExists greps /etc/passwd for ^name: — no NSS lookup needed for
// first-boot (local accounts only).
func (s *netbsdSystem) UserExists(name string) (bool, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false, err
	}
	defer f.Close()
	prefix := name + ":"
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), prefix) {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// CreateUser provisions a new user via useradd(8). chpass -a reads a
// passwd(5)-style line from stdin and accepts a pre-hashed crypt(3)
// value, so we never round-trip plaintext. Empty hash => useradd's
// default (locked) account is left as-is.
func (s *netbsdSystem) CreateUser(name, shell, passwordHash string, extraGroups []string) error {
	if shell == "" {
		shell = netbsdDefaultShell
	}
	for _, g := range extraGroups {
		if err := ensureGroup(g); err != nil {
			return fmt.Errorf("groupadd %s: %w", g, err)
		}
	}
	args := []string{"-m", "-s", shell}
	if len(extraGroups) > 0 {
		args = append(args, "-G", strings.Join(extraGroups, ","))
	}
	args = append(args, name)
	if out, err := exec.Command("/usr/sbin/useradd", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}

	if passwordHash == "" {
		// useradd creates a locked account by default ; nothing to do.
		s.log.Debug("netbsd: user created locked (no password hash)", "user", name)
		return nil
	}
	return setPasswordHash(name, passwordHash)
}

// ensureGroup runs groupadd ; NetBSD groupadd(8) returns 65 (EX_DATAERR)
// when the group already exists — we treat that as success.
func ensureGroup(group string) error {
	cmd := exec.Command("/usr/sbin/groupadd", group)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 65 {
		return nil
	}
	return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
}

// setPasswordHash feeds a passwd-style "user:hash" line into chpass -a,
// which is the documented way to push a pre-hashed value without going
// through a tty.
func setPasswordHash(name, hash string) error {
	cmd := exec.Command("/usr/sbin/chpass", "-a", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", name, hash))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chpass %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// AddUserToGroups unions extraGroups with the user's current groups
// because NetBSD's usermod -G REPLACES the supplementary list.
func (s *netbsdSystem) AddUserToGroups(name string, extraGroups []string) error {
	if len(extraGroups) == 0 {
		return nil
	}
	for _, g := range extraGroups {
		if err := ensureGroup(g); err != nil {
			return fmt.Errorf("groupadd %s: %w", g, err)
		}
	}
	current, err := currentGroups(name)
	if err != nil {
		return err
	}
	union := append([]string{}, current...)
	added := false
	for _, g := range extraGroups {
		if !contains(union, g) {
			union = append(union, g)
			added = true
		}
	}
	if !added {
		s.log.Debug("netbsd: user already in all requested groups", "user", name)
		return nil
	}
	args := []string{"-G", strings.Join(union, ","), name}
	if out, err := exec.Command("/usr/sbin/usermod", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("usermod %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// currentGroups reads supplementary groups via id -Gn.
func currentGroups(name string) ([]string, error) {
	out, err := exec.Command("/usr/bin/id", "-Gn", name).Output()
	if err != nil {
		return nil, fmt.Errorf("id -Gn %s: %w", name, err)
	}
	return strings.Fields(string(out)), nil
}

// AddAuthorizedKey appends key to ~user/.ssh/authorized_keys, creating
// the directory + file with strict perms+owner. Idempotent : an exact
// key match short-circuits.
func (s *netbsdSystem) AddAuthorizedKey(name, key string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", name, err)
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
	authFile := filepath.Join(sshDir, "authorized_keys")

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", sshDir, err)
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", sshDir, err)
	}

	keyTrim := strings.TrimSpace(key)
	if existing, err := os.ReadFile(authFile); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(existing))
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == keyTrim {
				s.log.Debug("netbsd: authorized_keys already has key", "user", name)
				return nil
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", authFile, err)
	}

	f, err := os.OpenFile(authFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", authFile, err)
	}
	defer f.Close()
	if _, err := f.WriteString(keyTrim + "\n"); err != nil {
		return fmt.Errorf("write %s: %w", authFile, err)
	}
	if err := os.Chmod(authFile, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", authFile, err)
	}
	if err := os.Chown(authFile, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", authFile, err)
	}
	return nil
}

// WriteFile lands content atomically. Owner/group/mode default to
// root:wheel 0644 (NetBSD root's primary group is wheel).
func (s *netbsdSystem) WriteFile(path, content, mode, owner, group string) error {
	m := os.FileMode(netbsdDefaultMode)
	if mode != "" {
		parsed, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return fmt.Errorf("parse mode %q: %w", mode, err)
		}
		m = os.FileMode(parsed)
	}
	if owner == "" {
		owner = netbsdDefaultOwner
	}
	if group == "" {
		group = netbsdDefaultGroup
	}
	uid, gid, err := lookupUIDGID(owner, group)
	if err != nil {
		return err
	}

	data := []byte(content)
	// Idempotent : skip when content+mode+owner+group all match.
	if existing, err := os.ReadFile(path); err == nil {
		if info, err := os.Stat(path); err == nil {
			if bytes.Equal(existing, data) && info.Mode().Perm() == m.Perm() && sameOwner(path, uid, gid) {
				s.log.Debug("netbsd: file already at target state", "path", path)
				return nil
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	return atomicWrite(path, data, m, uid, gid)
}

// lookupUIDGID resolves owner+group strings to numeric ids ; -1 sentinel
// means "do not chown" (used by rc.conf rewriter which keeps existing).
func lookupUIDGID(owner, group string) (int, int, error) {
	u, err := user.Lookup(owner)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %s: %w", owner, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %s: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid %q: %w", g.Gid, err)
	}
	return uid, gid, nil
}

// sameOwner returns true iff path is already owned by uid:gid.
func sameOwner(path string, uid, gid int) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(stat.Uid) == uid && int(stat.Gid) == gid
}

// atomicWrite is the standard write-temp-then-rename dance, scoped to
// the destination directory so rename(2) stays on one fs. uid/gid < 0
// skips chown (used when we want to preserve existing ownership).
func atomicWrite(path string, data []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".weft-firstboot-*")
	if err != nil {
		return fmt.Errorf("tempfile in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if uid >= 0 && gid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			tmp.Close()
			return fmt.Errorf("chown %s: %w", tmpName, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	cleanup = false
	return nil
}

// RunShell executes cmd via /bin/sh -c, wrapping output on failure so
// caller sees what the script actually printed.
func (s *netbsdSystem) RunShell(cmd string) error {
	s.log.Debug("netbsd: run shell", "cmd", cmd)
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sh -c %q: %w (%s)", cmd, err, strings.TrimSpace(string(out)))
	}
	return nil
}
