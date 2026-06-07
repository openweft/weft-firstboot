package apply

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/openweft/weft-firstboot/config"
)

// memSystem is the in-memory System used by every apply unit test.
// State is captured so assertions read like "did X happen exactly once
// with these args" rather than "what did the OS look like afterwards".
type memSystem struct {
	hostname        string
	hostnameSetCnt  int
	users           map[string]memUser
	files           map[string]memFile
	runShellCmds    []string
	addedAuthorized map[string][]string // user → keys (dedup-aware)
	addedToGroups   map[string][]string // user → group set
	// Error injection -- nil means succeed.
	runShellErr error
}

type memUser struct {
	shell        string
	passwordHash string
	groups       []string
}

type memFile struct {
	content string
	mode    string
	owner   string
	group   string
}

func newMemSystem() *memSystem {
	return &memSystem{
		users:           map[string]memUser{},
		files:           map[string]memFile{},
		addedAuthorized: map[string][]string{},
		addedToGroups:   map[string][]string{},
	}
}

func (m *memSystem) Hostname() (string, error)    { return m.hostname, nil }
func (m *memSystem) SetHostname(name string) error {
	m.hostname = name
	m.hostnameSetCnt++
	return nil
}
func (m *memSystem) UserExists(name string) (bool, error) {
	_, ok := m.users[name]
	return ok, nil
}
func (m *memSystem) CreateUser(name, shell, hash string, groups []string) error {
	if _, ok := m.users[name]; ok {
		return fmt.Errorf("CreateUser: %s already exists", name)
	}
	m.users[name] = memUser{shell: shell, passwordHash: hash, groups: append([]string(nil), groups...)}
	return nil
}
func (m *memSystem) AddUserToGroups(name string, groups []string) error {
	u, ok := m.users[name]
	if !ok {
		return fmt.Errorf("AddUserToGroups: %s does not exist", name)
	}
	for _, g := range groups {
		if !contains(u.groups, g) {
			u.groups = append(u.groups, g)
		}
		if !contains(m.addedToGroups[name], g) {
			m.addedToGroups[name] = append(m.addedToGroups[name], g)
		}
	}
	m.users[name] = u
	return nil
}
func (m *memSystem) AddAuthorizedKey(user, key string) error {
	for _, existing := range m.addedAuthorized[user] {
		if existing == key {
			return nil // idempotent
		}
	}
	m.addedAuthorized[user] = append(m.addedAuthorized[user], key)
	return nil
}
func (m *memSystem) WriteFile(path, content, mode, owner, group string) error {
	m.files[path] = memFile{content, mode, owner, group}
	return nil
}
func (m *memSystem) RunShell(cmd string) error {
	m.runShellCmds = append(m.runShellCmds, cmd)
	return m.runShellErr
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestApply_FullConfig(t *testing.T) {
	cfg := config.Config{
		Hostname: "vmd-test",
		Users: []config.User{
			{
				Name:              "openbsd",
				SSHAuthorizedKeys: []string{"ssh-ed25519 AAAA1", "ssh-ed25519 AAAA2"},
				Groups:            []string{"operator"},
				Doas:              true, // adds wheel
				Shell:             "/bin/ksh",
			},
		},
		WriteFiles: []config.File{
			{Path: "/etc/doas.conf", Content: "permit :wheel\n", Mode: "0640", Owner: "root", Group: "wheel"},
		},
		RunCmds: []string{"rcctl enable ntpd", "rcctl start ntpd"},
	}
	sys := newMemSystem()
	if err := Apply(cfg, sys, quietLog()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if sys.hostname != "vmd-test" {
		t.Errorf("hostname = %q", sys.hostname)
	}
	if sys.hostnameSetCnt != 1 {
		t.Errorf("SetHostname called %d times ; want 1", sys.hostnameSetCnt)
	}
	u, ok := sys.users["openbsd"]
	if !ok {
		t.Fatal("user openbsd not created")
	}
	if !contains(u.groups, "wheel") {
		t.Errorf("user openbsd should be in wheel (doas=true) ; groups=%v", u.groups)
	}
	if !contains(u.groups, "operator") {
		t.Errorf("user openbsd should be in operator (explicit) ; groups=%v", u.groups)
	}
	want := []string{"ssh-ed25519 AAAA1", "ssh-ed25519 AAAA2"}
	if !reflect.DeepEqual(sys.addedAuthorized["openbsd"], want) {
		t.Errorf("authorized_keys for openbsd = %v ; want %v", sys.addedAuthorized["openbsd"], want)
	}
	f, ok := sys.files["/etc/doas.conf"]
	if !ok {
		t.Fatal("/etc/doas.conf not written")
	}
	if f.content != "permit :wheel\n" || f.mode != "0640" || f.owner != "root" || f.group != "wheel" {
		t.Errorf("/etc/doas.conf = %+v", f)
	}
	wantCmds := []string{"rcctl enable ntpd", "rcctl start ntpd"}
	if !reflect.DeepEqual(sys.runShellCmds, wantCmds) {
		t.Errorf("RunShell calls = %v", sys.runShellCmds)
	}
}

func TestApply_IdempotentHostname(t *testing.T) {
	cfg := config.Config{Hostname: "vmd-test"}
	sys := newMemSystem()
	sys.hostname = "vmd-test" // already set
	if err := Apply(cfg, sys, quietLog()); err != nil {
		t.Fatal(err)
	}
	if sys.hostnameSetCnt != 0 {
		t.Errorf("SetHostname called %d times ; want 0 when already set", sys.hostnameSetCnt)
	}
}

func TestApply_IdempotentSSHKey(t *testing.T) {
	cfg := config.Config{
		Users: []config.User{{
			Name:              "openbsd",
			SSHAuthorizedKeys: []string{"ssh-ed25519 AAAA"},
		}},
	}
	sys := newMemSystem()
	if err := Apply(cfg, sys, quietLog()); err != nil {
		t.Fatal(err)
	}
	// Second apply : key should not be duplicated.
	if err := Apply(cfg, sys, quietLog()); err != nil {
		t.Fatal(err)
	}
	if got := len(sys.addedAuthorized["openbsd"]); got != 1 {
		t.Errorf("ssh key added %d times ; want 1 (idempotent)", got)
	}
}

func TestApply_ExistingUserGroupReconcile(t *testing.T) {
	// User exists, group requested -> AddUserToGroups, not CreateUser.
	sys := newMemSystem()
	sys.users["openbsd"] = memUser{shell: "/bin/ksh"}

	cfg := config.Config{
		Users: []config.User{{
			Name:   "openbsd",
			Groups: []string{"operator"},
			Doas:   true,
		}},
	}
	if err := Apply(cfg, sys, quietLog()); err != nil {
		t.Fatal(err)
	}
	added := sys.addedToGroups["openbsd"]
	for _, g := range []string{"operator", "wheel"} {
		if !contains(added, g) {
			t.Errorf("expected %s in addedToGroups ; got %v", g, added)
		}
	}
}

func TestApply_RuncmdFailureHaltsRest(t *testing.T) {
	sys := newMemSystem()
	sys.runShellErr = errors.New("boom")
	cfg := config.Config{
		RunCmds: []string{"cmd1", "cmd2"},
	}
	err := Apply(cfg, sys, quietLog())
	if err == nil || !strings.Contains(err.Error(), "runcmd #0") {
		t.Errorf("err = %v ; want runcmd #0", err)
	}
	if len(sys.runShellCmds) != 1 {
		t.Errorf("RunShell calls = %d ; want 1 (halt on first fail)", len(sys.runShellCmds))
	}
}
