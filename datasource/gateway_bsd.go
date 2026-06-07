//go:build openbsd || freebsd || netbsd

package datasource

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func init() {
	defaultGateway = bsdDefaultGateway
}

// bsdDefaultGateway invokes `route -n get default` (or `route get -inet default`
// on NetBSD's older syntax) and parses the "gateway: x.x.x.x" line.
//
// route(8) is in /sbin on every supported BSD. The "-n" suppresses DNS
// lookups, the "default" pseudo-destination matches 0.0.0.0/0. Exec is
// fine here because (a) route(8) is universally present, (b) the cost
// is one-shot at first-boot, (c) parsing PF_ROUTE messages from sysctl
// would otherwise need cgo or per-BSD socket-layer code.
func bsdDefaultGateway() (net.IP, error) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("route -n get default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		ip := net.ParseIP(gw)
		if ip == nil {
			return nil, fmt.Errorf("unparseable gateway %q", gw)
		}
		return ip, nil
	}
	return nil, errors.New("no default gateway in route output")
}
