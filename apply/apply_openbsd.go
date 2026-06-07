//go:build openbsd

package apply

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// openbsdSystem is the live-host System impl. It shells out to the
// base userland binaries (useradd/usermod/groupadd/hostname) rather
// than reimplementing passwd-database parsing in Go : the goal is
// "act like the operator would" so any postboot pwd_mkdb hook fires.
type openbsdSystem struct {
	log *slog.Logger
}

// NewOpenBSDSystem returns the System impl for OpenBSD hosts.
func NewOpenBSDSystem(log *slog.Logger) System {
	return &openbsdSystem{log: log}
}

// osNewSystem is the per-OS hook the factory in factory.go dispatches
// to. Build tags pick the right file ; no runtime switch needed here.
func osNewSystem(log *slog.Logger) System { return NewOpenBSDSystem(log) }

const (
	openbsdDefaultShell = "/bin/ksh"
	openbsdDefaultOwner = "root"
	// OpenBSD's root primary group is "wheel", not "root" — keep this
	// straight or chown calls below land the wrong gid.
	openbsdDefaultGroup = "wheel"
	openbsdDefaultMode  = 0o644
	openbsdMynameFile   = "/etc/myname"
)

// Hostname reads the running kernel name via os.Hostname so we reflect
// post-SetHostname state even before /etc/rc re-reads /etc/myname.
func (s *openbsdSystem) Hostname() (string, error) {
	return os.Hostname()
}

// SetHostname commits to /etc/myname (boot-time source via /etc/rc)
// AND applies live via hostname(1). Skips the write when /etc/myname
// already matches to avoid touching the file on every reboot.
func (s *openbsdSystem) SetHostname(name string) error {
	want := name + "\n"
	cur, err := os.ReadFile(openbsdMynameFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", openbsdMynameFile, err)
	}
	if string(cur) != want {
		if err := os.WriteFile(openbsdMynameFile, []byte(want), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", openbsdMynameFile, err)
		}
	} else {
		s.log.Debug("hostname file unchanged", "path", openbsdMynameFile)
	}
	if err := runCmd(s.log, "/bin/hostname", name); err != nil {
		return fmt.Errorf("hostname %s: %w", name, err)
	}
	return nil
}

// UserExists scans /etc/passwd for "^name:". Avoids relying on getent
// (not present on OpenBSD) and dodges os/user.Lookup's CGO path.
func (s *openbsdSystem) UserExists(name string) (bool, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false, fmt.Errorf("open /etc/passwd: %w", err)
	}
	defer f.Close()
	prefix := name + ":"
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		if strings.HasPrefix(scan.Text(), prefix) {
			return true, nil
		}
	}
	if err := scan.Err(); err != nil {
		return false, fmt.Errorf("scan /etc/passwd: %w", err)
	}
	return false, nil
}

// CreateUser provisions name with useradd(8). Groups that don't exist
// are created first with groupadd -o (tolerates dup gids/names). The
// password hash is set via usermod -p, which on OpenBSD accepts the
// pre-hashed value verbatim ; empty hash -> lock with '*'.
func (s *openbsdSystem) CreateUser(name, shell, passwordHash string, extraGroups []string) error {
	if shell == "" {
		shell = openbsdDefaultShell
	}
	if err := s.ensureGroups(extraGroups); err != nil {
		return err
	}
	args := []string{"-m", "-s", shell}
	if len(extraGroups) > 0 {
		args = append(args, "-G", strings.Join(extraGroups, ","))
	}
	args = append(args, name)
	if err := runCmd(s.log, "/usr/sbin/useradd", args...); err != nil {
		return fmt.Errorf("useradd %s: %w", name, err)
	}
	hash := passwordHash
	if hash == "" {
		hash = "*"
	}
	if err := runCmd(s.log, "/usr/sbin/usermod", "-p", hash, name); err != nil {
		return fmt.Errorf("usermod -p %s: %w", name, err)
	}
	return nil
}

// AddUserToGroups reconciles supplementary groups on an existing user
// via usermod -G. Missing groups are groupadd'd first ; useradd/usermod
// would otherwise refuse the whole call.
func (s *openbsdSystem) AddUserToGroups(name string, extraGroups []string) error {
	if len(extraGroups) == 0 {
		s.log.Debug("no extra groups requested", "user", name)
		return nil
	}
	if err := s.ensureGroups(extraGroups); err != nil {
		return err
	}
	if err := runCmd(s.log, "/usr/sbin/usermod", "-G", strings.Join(extraGroups, ","), name); err != nil {
		return fmt.Errorf("usermod -G %s: %w", name, err)
	}
	return nil
}

// ensureGroups groupadds anything missing, -o so an already-existing
// name returns 0 instead of failing the whole apply pass.
func (s *openbsdSystem) ensureGroups(groups []string) error {
	for _, g := range groups {
		if g == "" {
			continue
		}
		if err := runCmd(s.log, "/usr/sbin/groupadd", "-o", g); err != nil {
			return fmt.Errorf("groupadd %s: %w", g, err)
		}
	}
	return nil
}

// AddAuthorizedKey appends key to ~user/.ssh/authorized_keys, creating
// the directory + file with the strict perms sshd requires. uid/gid
// come from the user's passwd entry so the file ends up owned by the
// real user (not "wheel" — that's a sshd StrictModes trap).
func (s *openbsdSystem) AddAuthorizedKey(username, key string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}
	sshDir := filepath.Join(u.HomeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", sshDir, err)
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", sshDir, err)
	}
	authFile := filepath.Join(sshDir, "authorized_keys")
	existing, err := os.ReadFile(authFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", authFile, err)
	}
	trimmedKey := strings.TrimSpace(key)
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == trimmedKey {
			s.log.Debug("ssh key already present", "user", username)
			return nil
		}
	}
	buf := existing
	if len(buf) > 0 && !bytes.HasSuffix(buf, []byte("\n")) {
		buf = append(buf, '\n')
	}
	buf = append(buf, []byte(trimmedKey+"\n")...)
	if err := os.WriteFile(authFile, buf, 0o600); err != nil {
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

// WriteFile lands content atomically (tempfile in same dir + rename)
// so a crash mid-write never leaves a half-baked /etc/doas.conf. Diffs
// content+mode+owner+group ; only re-writes on actual change.
func (s *openbsdSystem) WriteFile(path, content, mode, owner, group string) error {
	if owner == "" {
		owner = openbsdDefaultOwner
	}
	if group == "" {
		group = openbsdDefaultGroup
	}
	m, err := parseMode(mode, openbsdDefaultMode)
	if err != nil {
		return fmt.Errorf("parse mode %q: %w", mode, err)
	}
	uid, gid, err := lookupOwner(owner, group)
	if err != nil {
		return err
	}
	if same, err := fileMatches(path, content, m, uid, gid); err != nil {
		return err
	} else if same {
		s.log.Debug("file unchanged", "path", path)
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
		tmp.Close()
		cleanup()
		return fmt.Errorf("write tempfile: %w", err)
	}
	if err := tmp.Chmod(m); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tempfile: %w", err)
	}
	if err := os.Chown(tmpPath, uid, gid); err != nil {
		cleanup()
		return fmt.Errorf("chown tempfile: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// fileMatches reports whether path already has the desired content+
// mode+uid+gid ; missing-file returns (false, nil) so caller writes.
func fileMatches(path, content string, mode os.FileMode, uid, gid int) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode().Perm() != mode.Perm() {
		return false, nil
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false, nil
	}
	if int(sys.Uid) != uid || int(sys.Gid) != gid {
		return false, nil
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return string(existing) == content, nil
}

// parseMode accepts octal ("0644", "644", "0o644") ; empty → default.
func parseMode(mode string, dflt os.FileMode) (os.FileMode, error) {
	if mode == "" {
		return dflt, nil
	}
	s := mode
	s = strings.TrimPrefix(s, "0o")
	s = strings.TrimPrefix(s, "0O")
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(n), nil
}

// lookupOwner resolves user+group names to uid:gid, leaning on
// os/user (which on OpenBSD reads /etc/passwd directly, no NSS).
func lookupOwner(owner, group string) (int, int, error) {
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
		return 0, 0, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q: %w", g.Gid, err)
	}
	return uid, gid, nil
}

// PackageInstall calls pkg_add(1) with -I (non-interactive : reject any
// prompt instead of hanging at the install). pkg_add resolves package
// specs against the PKG_PATH set in the environment (defaulting to the
// installurl on /etc/installurl). pkg_add is idempotent : already-
// installed packages are reported and skipped.
func (s *openbsdSystem) PackageInstall(pkgs []string) error {
	if len(pkgs) == 0 {
		return nil
	}
	s.log.Info("package install", "pkgs", pkgs)
	argv := append([]string{"-I"}, pkgs...)
	c := exec.Command("/usr/sbin/pkg_add", argv...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Run(); err != nil {
		return fmt.Errorf("pkg_add %v: %w (output: %s)", pkgs, err, strings.TrimSpace(out.String()))
	}
	return nil
}

// RunShell hands cmd to /bin/sh -c. stdout+stderr are blended into the
// error on non-zero exit so the operator sees what the script printed.
func (s *openbsdSystem) RunShell(cmd string) error {
	c := exec.Command("/bin/sh", "-c", cmd)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	if err != nil {
		s.log.Debug("runshell failed", "cmd", cmd, "err", err, "output", out.String())
		return fmt.Errorf("sh -c %q: %w (output: %s)", cmd, err, strings.TrimSpace(out.String()))
	}
	s.log.Debug("runshell ok", "cmd", cmd)
	return nil
}

// runCmd executes name with args, blending output into the error on
// failure. Shared by SetHostname / useradd / usermod / groupadd.
func runCmd(log *slog.Logger, name string, args ...string) error {
	c := exec.Command(name, args...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Run(); err != nil {
		log.Debug("cmd failed", "name", name, "args", args, "err", err, "output", out.String())
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	log.Debug("cmd ok", "name", name, "args", args)
	return nil
}
