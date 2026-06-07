package config

import (
	"fmt"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// hclConfig mirrors Config but with HCL struct tags. Kept private so the
// public Config stays cleanly format-agnostic (cloud-config YAML decodes
// into its own type then converts to Config the same way).
type hclConfig struct {
	Hostname   string         `hcl:"hostname,optional"`
	Users      []hclUser      `hcl:"user,block"`
	WriteFiles []hclWriteFile `hcl:"write_file,block"`
	Packages   []string       `hcl:"packages,optional"`
	RunCmds    []string       `hcl:"runcmd,optional"`
}

type hclUser struct {
	Name              string   `hcl:"name,label"`
	SSHAuthorizedKeys []string `hcl:"ssh_authorized_keys,optional"`
	Groups            []string `hcl:"groups,optional"`
	Sudo              bool     `hcl:"sudo,optional"`
	Doas              bool     `hcl:"doas,optional"`
	Shell             string   `hcl:"shell,optional"`
	PasswordHash      string   `hcl:"password_hash,optional"`
}

type hclWriteFile struct {
	Path    string `hcl:"path,label"`
	Content string `hcl:"content"`
	Mode    string `hcl:"mode,optional"`
	Owner   string `hcl:"owner,optional"`
	Group   string `hcl:"group,optional"`
}

// ParseHCL decodes raw HCL bytes from filename (used in diagnostics only).
func ParseHCL(filename string, src []byte) (Config, error) {
	p := hclparse.NewParser()
	f, diags := p.ParseHCL(src, filename)
	if diags.HasErrors() {
		return Config{}, fmt.Errorf("parse: %s", diags.Error())
	}
	var raw hclConfig
	if diags := gohcl.DecodeBody(f.Body, nil, &raw); diags.HasErrors() {
		return Config{}, fmt.Errorf("decode: %s", diags.Error())
	}
	return hclToConfig(raw), nil
}

func hclToConfig(raw hclConfig) Config {
	users := make([]User, len(raw.Users))
	for i, u := range raw.Users {
		users[i] = User{
			Name:              u.Name,
			SSHAuthorizedKeys: u.SSHAuthorizedKeys,
			Groups:            u.Groups,
			Sudo:              u.Sudo,
			Doas:              u.Doas,
			Shell:             u.Shell,
			PasswordHash:      u.PasswordHash,
		}
	}
	files := make([]File, len(raw.WriteFiles))
	for i, f := range raw.WriteFiles {
		files[i] = File{
			Path:    f.Path,
			Content: f.Content,
			Mode:    f.Mode,
			Owner:   f.Owner,
			Group:   f.Group,
		}
	}
	return Config{
		Hostname:   raw.Hostname,
		Users:      users,
		WriteFiles: files,
		Packages:   raw.Packages,
		RunCmds:    raw.RunCmds,
	}
}
