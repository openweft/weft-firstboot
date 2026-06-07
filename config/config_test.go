package config

import (
	"reflect"
	"testing"
)

// TestParseHCL_FullExample exercises every block type at once : the
// vmd-test VM's actual first-boot config is the regression fixture.
func TestParseHCL_FullExample(t *testing.T) {
	src := []byte(`
hostname = "vmd-test"

user "openbsd" {
  ssh_authorized_keys = [
    "ssh-ed25519 AAAA1",
    "ssh-ed25519 AAAA2",
  ]
  groups = ["wheel"]
  doas   = true
  shell  = "/bin/ksh"
}

user "root" {
  ssh_authorized_keys = ["ssh-ed25519 AAAA3"]
}

write_file "/etc/doas.conf" {
  content = "permit nopass keepenv :wheel\n"
  mode    = "0640"
  owner   = "root"
  group   = "wheel"
}

runcmd = [
  "rcctl enable ntpd",
  "rcctl start ntpd",
]
`)
	got, err := ParseHCL("test.hcl", src)
	if err != nil {
		t.Fatalf("ParseHCL: %v", err)
	}
	want := Config{
		Hostname: "vmd-test",
		Users: []User{
			{
				Name:              "openbsd",
				SSHAuthorizedKeys: []string{"ssh-ed25519 AAAA1", "ssh-ed25519 AAAA2"},
				Groups:            []string{"wheel"},
				Doas:              true,
				Shell:             "/bin/ksh",
			},
			{
				Name:              "root",
				SSHAuthorizedKeys: []string{"ssh-ed25519 AAAA3"},
			},
		},
		WriteFiles: []File{
			{
				Path:    "/etc/doas.conf",
				Content: "permit nopass keepenv :wheel\n",
				Mode:    "0640",
				Owner:   "root",
				Group:   "wheel",
			},
		},
		RunCmds: []string{"rcctl enable ntpd", "rcctl start ntpd"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseHCL got %+v\n want %+v", got, want)
	}
}

// TestParseHCL_Packages : packages list parses as a top-level attribute.
func TestParseHCL_Packages(t *testing.T) {
	src := []byte(`packages = ["nginx", "vim", "tmux"]`)
	got, err := ParseHCL("test.hcl", src)
	if err != nil {
		t.Fatalf("ParseHCL: %v", err)
	}
	want := []string{"nginx", "vim", "tmux"}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("Packages = %v ; want %v", got.Packages, want)
	}
}

// TestParseCloudConfig_Packages : both string entries and [name, version]
// pairs map to the bare package name (versions dropped — the OS pkg
// manager handles version pinning via its own syntax).
func TestParseCloudConfig_Packages(t *testing.T) {
	src := []byte(`
packages:
  - nginx
  - [vim, "9.0"]
  - tmux
`)
	got, err := ParseCloudConfig(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nginx", "vim", "tmux"}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("Packages = %v ; want %v", got.Packages, want)
	}
}

// TestParseHCL_Empty : empty HCL is valid (no-op config).
func TestParseHCL_Empty(t *testing.T) {
	got, err := ParseHCL("test.hcl", []byte(""))
	if err != nil {
		t.Fatalf("ParseHCL: %v", err)
	}
	if got.Hostname != "" || len(got.Users) != 0 || len(got.WriteFiles) != 0 || len(got.RunCmds) != 0 {
		t.Errorf("empty HCL produced non-empty Config : %+v", got)
	}
}

// TestParseHCL_Malformed : surface a useful error, don't panic.
func TestParseHCL_Malformed(t *testing.T) {
	_, err := ParseHCL("test.hcl", []byte("not a valid { hcl"))
	if err == nil {
		t.Error("expected error on malformed HCL")
	}
}

// TestParseCloudConfig_Subset : the subset we advertise actually maps.
func TestParseCloudConfig_Subset(t *testing.T) {
	src := []byte(`#cloud-config
hostname: vmd-test
users:
  - name: openbsd
    ssh_authorized_keys:
      - ssh-ed25519 AAAA1
    groups: wheel, operator
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/ksh
write_files:
  - path: /etc/doas.conf
    content: |
      permit nopass keepenv :wheel
    permissions: '0640'
    owner: root:wheel
runcmd:
  - rcctl enable ntpd
  - [rcctl, start, ntpd]
bootcmd:
  - echo booting
`)
	got, err := ParseCloudConfig(src)
	if err != nil {
		t.Fatalf("ParseCloudConfig: %v", err)
	}
	if got.Hostname != "vmd-test" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
	if len(got.Users) != 1 || got.Users[0].Name != "openbsd" {
		t.Fatalf("Users = %+v", got.Users)
	}
	u := got.Users[0]
	if !reflect.DeepEqual(u.Groups, []string{"wheel", "operator"}) {
		t.Errorf("Users[0].Groups = %v", u.Groups)
	}
	if !u.Sudo {
		t.Error("Users[0].Sudo should be true for non-empty cloud-config sudo")
	}
	if len(got.WriteFiles) != 1 || got.WriteFiles[0].Owner != "root" || got.WriteFiles[0].Group != "wheel" {
		t.Errorf("WriteFiles = %+v", got.WriteFiles)
	}
	// bootcmd lands before runcmd, both flattened.
	want := []string{"echo booting", "rcctl enable ntpd", "rcctl start ntpd"}
	if !reflect.DeepEqual(got.RunCmds, want) {
		t.Errorf("RunCmds = %v ; want %v", got.RunCmds, want)
	}
}

// TestParseCloudConfig_NoMagicHeader : header is optional.
func TestParseCloudConfig_NoMagicHeader(t *testing.T) {
	src := []byte(`hostname: vmd-test`)
	got, err := ParseCloudConfig(src)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "vmd-test" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
}

// TestParseCloudConfig_RunCmdShellQuote : list-of-strings entries are joined
// with shell quoting so `["echo", "hello world"]` stays one logical token.
func TestParseCloudConfig_RunCmdShellQuote(t *testing.T) {
	src := []byte(`
runcmd:
  - [echo, hello world]
  - [printf, '%s\n', test]
`)
	got, err := ParseCloudConfig(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`echo 'hello world'`, `printf '%s\n' test`}
	if !reflect.DeepEqual(got.RunCmds, want) {
		t.Errorf("RunCmds = %v\n want %v", got.RunCmds, want)
	}
}
