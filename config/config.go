// Package config defines the weft-firstboot configuration schema and its
// parsers. HCL is the primary format ; cloud-config YAML is a legacy bridge
// so VMs built from someone else's Ubuntu user-data still come up clean
// without a per-format rewrite.
//
// The Config struct is the lowest common denominator across Linux, OpenBSD,
// FreeBSD and NetBSD : every field maps to a primitive that the apply
// package's System interface can act on. Anything OS-specific (rcctl vs
// systemctl, useradd flags, /etc layout) lives behind that interface, not
// in the config types.
package config

// Config is the parsed, normalised first-boot directive set. Apply order :
//
//   1. SetHostname
//   2. WriteFiles  (in declaration order)
//   3. CreateUsers (in declaration order ; each user's authorized_keys
//      land after the user's home is created)
//   4. RunCmds     (in declaration order, fail-fast on non-zero exit)
//
// Idempotence is required at the System layer : re-running a Config
// against an already-provisioned host should be a no-op, not an error.
// First-boot semantics are guaranteed by the caller writing a sentinel
// file (typically /var/lib/weft-firstboot/applied) after success and
// short-circuiting on subsequent runs.
type Config struct {
	// Hostname is set via the OS-native mechanism (hostnamectl on systemd,
	// /etc/myname + hostname(1) on OpenBSD, sysrc on FreeBSD, /etc/rc.conf
	// on NetBSD). Empty means leave the hostname untouched.
	Hostname string

	// Users are created in declaration order. Existing users are kept ;
	// only their authorized_keys / shell / groups membership is
	// reconciled. Removing a user is out of scope for V0.1 (would
	// conflict with the long-lived user that ran the install).
	Users []User

	// WriteFiles are landed before users are created so e.g. /etc/doas.conf
	// can be in place before the wheel user is added.
	WriteFiles []File

	// RunCmds are POSIX-sh strings (passed to `sh -c <cmd>`). Non-zero
	// exit aborts further apply. Use this for the long tail : `rcctl
	// enable nginx`, `useradd -G docker $USER`, etc.
	RunCmds []string
}

// User is one entry in the users list.
type User struct {
	Name              string
	SSHAuthorizedKeys []string
	// Groups the user is added to (created if missing). The primary group
	// is OS-default (usually a same-named group).
	Groups []string
	// Sudo grants passwordless sudo on Linux. On OpenBSD this is a no-op ;
	// use Doas instead (and write /etc/doas.conf via WriteFiles).
	Sudo bool
	// Doas grants passwordless doas on OpenBSD. We don't write
	// /etc/doas.conf ourselves (it merges with existing rules) -- the
	// caller does it via WriteFiles. Doas=true just means "this user is
	// in the wheel group so doas can match them".
	Doas bool
	// Shell defaults to a sensible per-OS value (bash on Linux/FreeBSD,
	// ksh on OpenBSD/NetBSD) when empty.
	Shell string
	// PasswordHash is a crypt(3)-style hash ($2b$..., $6$..., $y$...).
	// Empty means lock the password (key-only login).
	PasswordHash string
}

// File is one entry in the write_files list.
type File struct {
	Path    string
	Content string
	// Mode in octal string form ("0644"). Empty defaults to "0644".
	Mode string
	// Owner / Group default to "root" / OS-default-root-group ("root" on
	// Linux/FreeBSD/NetBSD, "wheel" on OpenBSD).
	Owner string
	Group string
}
