// Package apply turns a parsed Config into actual host mutations. The
// System interface abstracts the OS primitives ; per-OS implementations
// live in apply_<os>.go behind build tags.
//
// All System calls must be idempotent. A first-boot agent is allowed
// to crash and resume ; on resume, replaying the same Config against
// the same host must be a no-op rather than an error or a duplicate
// effect.
package apply

import (
	"fmt"
	"log/slog"

	"github.com/openweft/weft-firstboot/config"
)

// System is the OS abstraction the apply layer talks to. Every method
// is idempotent : SetHostname on a host already named X is a no-op,
// CreateUser on an existing user only reconciles authorized_keys /
// shell / group membership, WriteFile compares content + mode + owner
// and only re-writes on diff.
type System interface {
	// Hostname returns the live hostname (post any previous SetHostname).
	Hostname() (string, error)
	// SetHostname commits the new name to durable config (/etc/hostname,
	// /etc/myname, /etc/rc.conf depending on OS) AND applies it to the
	// running kernel via the native command.
	SetHostname(name string) error

	// UserExists reports whether name appears in the passwd database.
	UserExists(name string) (bool, error)
	// CreateUser provisions a new user with the given primary shell ;
	// the user's primary group is left to OS defaults (per-OS useradd
	// behaviour). Groups in extraGroups are appended (created if
	// missing). passwordHash, when non-empty, becomes the crypt(3)
	// hash ; empty hash locks the password.
	CreateUser(name, shell, passwordHash string, extraGroups []string) error
	// AddUserToGroups appends extraGroups to an EXISTING user's
	// supplementary groups. Used on the reconcile path so re-runs
	// against an already-provisioned host catch up new group adds.
	AddUserToGroups(name string, extraGroups []string) error
	// AddAuthorizedKey appends key to user's ~/.ssh/authorized_keys
	// (creating the directory + file with the right perms+owner).
	// Re-adding an already-present key is a no-op.
	AddAuthorizedKey(user, key string) error

	// WriteFile lands content at path with the given mode + ownership.
	// Existing files are diffed ; only on differing content/mode/owner
	// is the file overwritten (atomic rename via tempfile).
	WriteFile(path, content, mode, owner, group string) error

	// RunShell executes cmd via the OS sh, returning stdout/stderr
	// blended on a non-zero exit. The implementation logs the command
	// + outcome at debug level.
	RunShell(cmd string) error
}

// Apply walks cfg in the documented order and invokes the matching
// System primitive for each entry. Halts on the first error.
//
// log is non-nil and used for per-step trace ("set hostname",
// "write_file /etc/doas.conf", "user openbsd created", "runcmd #3 ok").
func Apply(cfg config.Config, sys System, log *slog.Logger) error {
	if cfg.Hostname != "" {
		current, _ := sys.Hostname()
		if current != cfg.Hostname {
			log.Info("setting hostname", "from", current, "to", cfg.Hostname)
			if err := sys.SetHostname(cfg.Hostname); err != nil {
				return fmt.Errorf("set hostname %q: %w", cfg.Hostname, err)
			}
		} else {
			log.Debug("hostname unchanged", "name", current)
		}
	}

	for _, f := range cfg.WriteFiles {
		log.Info("write file", "path", f.Path, "mode", f.Mode)
		if err := sys.WriteFile(f.Path, f.Content, f.Mode, f.Owner, f.Group); err != nil {
			return fmt.Errorf("write_file %s: %w", f.Path, err)
		}
	}

	for _, u := range cfg.Users {
		exists, err := sys.UserExists(u.Name)
		if err != nil {
			return fmt.Errorf("user %s: probe: %w", u.Name, err)
		}
		// Doas+Sudo both imply membership in the "wheel" group ; we
		// fold that into the requested groups here so the OS-specific
		// CreateUser doesn't have to special-case it.
		groups := u.Groups
		if (u.Doas || u.Sudo) && !contains(groups, "wheel") {
			groups = append(groups, "wheel")
		}
		if !exists {
			log.Info("create user", "name", u.Name, "groups", groups)
			if err := sys.CreateUser(u.Name, u.Shell, u.PasswordHash, groups); err != nil {
				return fmt.Errorf("user %s: create: %w", u.Name, err)
			}
		} else {
			log.Debug("user exists ; reconciling groups", "name", u.Name)
			if err := sys.AddUserToGroups(u.Name, groups); err != nil {
				return fmt.Errorf("user %s: groups: %w", u.Name, err)
			}
		}
		for _, key := range u.SSHAuthorizedKeys {
			if err := sys.AddAuthorizedKey(u.Name, key); err != nil {
				return fmt.Errorf("user %s: ssh key: %w", u.Name, err)
			}
		}
	}

	for i, cmd := range cfg.RunCmds {
		log.Info("runcmd", "i", i, "cmd", cmd)
		if err := sys.RunShell(cmd); err != nil {
			return fmt.Errorf("runcmd #%d (%q): %w", i, cmd, err)
		}
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
