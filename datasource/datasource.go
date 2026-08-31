// Package datasource locates the first-boot configuration. V0.1 supports
// two flavours of the NoCloud datasource :
//
//	nocloud-net : HTTP fetch of user-data + meta-data (cloud-init's
//	              standard "fetch from a web server pointed at by DHCP")
//	nocloud     : block device with a filesystem label "cidata" or
//	              "CIDATA" holding /user-data + /meta-data
//
// The nocloud disk is read *without mounting it* : the candidate device
// nodes are opened read-only and their on-disk structures decoded in
// pure Go (go-filesystems/detect picks the driver from the magic
// signature). No mount(2), no /sbin/mount_* fork, no root. A mount
// fallback survives for filesystem shapes the pure-Go drivers cannot
// read yet — see fromDisk in disk.go — and Source.Origin always says
// which of the two served.
//
// The configuration format inside the datasource is auto-detected : if
// user-data starts with "#cloud-config" or is parseable as YAML, we treat
// it as cloud-config legacy ; otherwise we parse as HCL. The HCL path is
// preferred for new VMs (no magic header needed).
//
// Discovery order, from cheapest to most invasive :
//
//  1. --datasource URL              explicit override (highest priority)
//  2. NoCloud disk (cidata label)   no network, no privilege : a
//     read-only open plus a few bounded reads per candidate device
//  3. NoCloud-NET via HTTP          one DHCP probe + one GET
package datasource

import (
	"errors"
	"fmt"

	"github.com/openweft/weft-firstboot/config"
)

// ErrNotFound is returned by individual probes when their datasource
// flavour wasn't present. The Discover function aggregates probes and
// only fails when every probe returned ErrNotFound.
var ErrNotFound = errors.New("datasource: not found")

// Source is the result of a successful probe : the raw user-data bytes
// (so we can record a hash for idempotence) plus the parsed Config.
type Source struct {
	// Origin describes where the data came from, e.g.
	// "nocloud-net:http://10.0.2.2/user-data" or "nocloud:/dev/sd1a".
	// Used for logging and the sentinel file's record.
	Origin string
	// Raw is the unparsed user-data bytes. Useful for hashing to skip
	// re-apply on already-converged hosts.
	Raw []byte
	// Config is the parsed Config (HCL or cloud-config YAML).
	Config config.Config
}

// Discover runs every available probe (CLI override, disk, HTTP) until
// one succeeds. Returns ErrNotFound if no flavour matched.
//
// The override URL, when non-empty, supersedes auto-discovery — useful
// for testing and for autoinstall flows where the URL is pinned.
func Discover(override string) (Source, error) {
	probes := []func() (Source, error){}
	if override != "" {
		probes = append(probes, func() (Source, error) {
			return fromHTTP(override)
		})
	} else {
		probes = append(probes,
			fromDisk,
			fromDefaultGatewayHTTP,
		)
	}
	for _, probe := range probes {
		src, err := probe()
		if err == nil {
			return src, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return Source{}, err
		}
	}
	return Source{}, ErrNotFound
}

// Parse routes raw bytes through the right parser. Heuristic :
//   - first non-whitespace line is "#cloud-config" → cloud-config YAML
//   - else default to HCL (the preferred format)
//
// We don't try to parse-and-fallback because HCL and YAML can both
// silently consume each other's syntax in pathological cases ; the
// explicit header keeps the choice deterministic.
//
// Exported so the CLI can parse a local file without going through
// Discover (which would mis-tag a file URL as "nocloud-net:").
func Parse(raw []byte) (config.Config, error) {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c == '#' && len(raw) >= i+len("#cloud-config") &&
			string(raw[i:i+len("#cloud-config")]) == "#cloud-config" {
			return config.ParseCloudConfig(raw)
		}
		break
	}
	cfg, err := config.ParseHCL("user-data", raw)
	if err != nil {
		return config.Config{}, fmt.Errorf("user-data parse: %w", err)
	}
	return cfg, nil
}
