package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// cloudConfigYAML is a deliberate SUBSET of cloud-config :
//
//   hostname / fqdn       -> Hostname
//   users[].name          -> User.Name
//   users[].ssh_authorized_keys -> User.SSHAuthorizedKeys
//   users[].groups        -> User.Groups
//   users[].sudo          -> User.Sudo (any non-empty string means yes)
//   users[].shell         -> User.Shell
//   users[].passwd        -> User.PasswordHash
//   write_files[]         -> WriteFiles (path/content/permissions/owner)
//   runcmd[]              -> RunCmds (list of strings ; list-of-lists
//                                     is flattened to "arg arg arg")
//
// EVERYTHING ELSE in cloud-config is silently ignored. The legacy parser
// exists to onboard existing Ubuntu/Debian user-data with minimal friction,
// not to be a drop-in cloud-init.
type cloudConfigYAML struct {
	Hostname   string                 `yaml:"hostname,omitempty"`
	FQDN       string                 `yaml:"fqdn,omitempty"`
	Users      []cloudUser            `yaml:"users,omitempty"`
	WriteFiles []cloudWriteFile       `yaml:"write_files,omitempty"`
	Packages   []any                  `yaml:"packages,omitempty"` // string or [name, ver]
	RunCmd     []any                  `yaml:"runcmd,omitempty"`
	BootCmd    []any                  `yaml:"bootcmd,omitempty"`
	_          map[string]interface{} `yaml:",inline"` // tolerate unknown fields
}

type cloudUser struct {
	Name              string   `yaml:"name"`
	SSHAuthorizedKeys []string `yaml:"ssh_authorized_keys,omitempty"`
	Groups            any      `yaml:"groups,omitempty"` // string or []string
	Sudo              any      `yaml:"sudo,omitempty"`   // string or bool
	Shell             string   `yaml:"shell,omitempty"`
	Passwd            string   `yaml:"passwd,omitempty"`
}

type cloudWriteFile struct {
	Path        string `yaml:"path"`
	Content     string `yaml:"content"`
	Permissions string `yaml:"permissions,omitempty"`
	Owner       string `yaml:"owner,omitempty"` // "user:group" or just "user"
}

// ParseCloudConfig decodes the YAML SUBSET. The "#cloud-config" magic
// header on line 1 is optional ; the parser handles either form.
func ParseCloudConfig(src []byte) (Config, error) {
	// Strip the optional magic header so the YAML decoder sees pure YAML.
	if bytes := strings.TrimSpace(string(src)); strings.HasPrefix(bytes, "#cloud-config") {
		nl := strings.IndexByte(bytes, '\n')
		if nl < 0 {
			src = nil
		} else {
			src = []byte(bytes[nl+1:])
		}
	}
	var raw cloudConfigYAML
	if err := yaml.Unmarshal(src, &raw); err != nil {
		return Config{}, fmt.Errorf("yaml: %w", err)
	}
	return cloudToConfig(raw), nil
}

func cloudToConfig(raw cloudConfigYAML) Config {
	host := raw.Hostname
	if host == "" {
		host = raw.FQDN
	}
	users := make([]User, 0, len(raw.Users))
	for _, u := range raw.Users {
		// cloud-config special value : users: [default] (singleton string
		// instead of map). Skip silently — we don't model the default user.
		if u.Name == "" {
			continue
		}
		users = append(users, User{
			Name:              u.Name,
			SSHAuthorizedKeys: u.SSHAuthorizedKeys,
			Groups:            normaliseGroups(u.Groups),
			Sudo:              normaliseSudo(u.Sudo),
			Shell:             u.Shell,
			PasswordHash:      u.Passwd,
		})
	}
	files := make([]File, len(raw.WriteFiles))
	for i, f := range raw.WriteFiles {
		owner, group := splitOwner(f.Owner)
		files[i] = File{
			Path:    f.Path,
			Content: f.Content,
			Mode:    f.Permissions,
			Owner:   owner,
			Group:   group,
		}
	}
	cmds := flattenRunCmd(raw.BootCmd)
	cmds = append(cmds, flattenRunCmd(raw.RunCmd)...)
	return Config{
		Hostname:   host,
		Users:      users,
		WriteFiles: files,
		Packages:   flattenPackages(raw.Packages),
		RunCmds:    cmds,
	}
}

// flattenPackages accepts cloud-config's loose shape : entries can be
// strings ("nginx") OR string-arrays for [name, version] pinning
// (["nginx", "1.24.0"] -- we drop the version since the OS-native
// package managers handle that via their own syntax and we don't
// translate). Anything else is silently skipped.
func flattenPackages(v []any) []string {
	out := make([]string, 0, len(v))
	for _, entry := range v {
		switch x := entry.(type) {
		case string:
			if x != "" {
				out = append(out, x)
			}
		case []any:
			// First element is the name -- versions are ignored.
			if len(x) > 0 {
				if name, ok := x[0].(string); ok && name != "" {
					out = append(out, name)
				}
			}
		}
	}
	return out
}

func normaliseGroups(v any) []string {
	switch g := v.(type) {
	case string:
		// cloud-config allows "groups: wheel, sudo, adm" — comma-separated.
		out := []string{}
		for _, part := range strings.Split(g, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(g))
		for _, x := range g {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func normaliseSudo(v any) bool {
	switch s := v.(type) {
	case bool:
		return s
	case string:
		// "ALL=(ALL) NOPASSWD:ALL" -> we treat any non-empty as "grant sudo"
		return strings.TrimSpace(s) != ""
	}
	return false
}

func splitOwner(s string) (owner, group string) {
	if s == "" {
		return "", ""
	}
	parts := strings.SplitN(s, ":", 2)
	owner = parts[0]
	if len(parts) > 1 {
		group = parts[1]
	}
	return
}

// flattenRunCmd accepts cloud-config's union shape : runcmd entries can be
// strings (passed straight to sh -c) OR string-arrays (joined with spaces ;
// each arg is shell-quoted to preserve semantics). Anything else is dropped.
func flattenRunCmd(v []any) []string {
	out := make([]string, 0, len(v))
	for _, entry := range v {
		switch x := entry.(type) {
		case string:
			out = append(out, x)
		case []any:
			parts := make([]string, 0, len(x))
			for _, a := range x {
				if s, ok := a.(string); ok {
					parts = append(parts, shellQuote(s))
				}
			}
			out = append(out, strings.Join(parts, " "))
		}
	}
	return out
}

// shellQuote single-quotes a string for sh ; ' inside becomes '\''.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`*?[]&;|<>(){}#~!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
