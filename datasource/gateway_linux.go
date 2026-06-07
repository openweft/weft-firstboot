//go:build linux

package datasource

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func init() {
	defaultGateway = linuxDefaultGateway
}

// linuxDefaultGateway parses /proc/net/route. The kernel exposes the
// routing table here as a tab-separated text file with hex-encoded
// little-endian addresses. Picking the row with Destination == 0 and
// the lowest Metric gives the default route.
//
// /proc is available in every Linux kernel we ship to ; netlink would
// be cleaner but adds a sizeable dependency (or syscall wiring) for a
// single read at first-boot — not worth the complexity yet.
func linuxDefaultGateway() (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan() // skip header
	best := struct {
		gw     net.IP
		metric uint64
	}{metric: ^uint64(0)}
	for s.Scan() {
		fields := strings.Fields(s.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		if len(fields) < 8 {
			continue
		}
		if fields[1] != "00000000" { // not the default route
			continue
		}
		gw, err := hexLEIPv4(fields[2])
		if err != nil {
			continue
		}
		metric, _ := strconv.ParseUint(fields[6], 10, 64)
		if metric < best.metric {
			best.gw = gw
			best.metric = metric
		}
	}
	if best.gw == nil {
		return nil, errors.New("no default route in /proc/net/route")
	}
	return best.gw, nil
}

// hexLEIPv4 decodes "0202000A" -> 10.0.2.2. Linux's /proc/net/route uses
// little-endian hex for IPv4 addresses.
func hexLEIPv4(s string) (net.IP, error) {
	if len(s) != 8 {
		return nil, fmt.Errorf("bad ipv4 hex length: %q", s)
	}
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		b, err := strconv.ParseUint(s[6-2*i:8-2*i], 16, 8)
		if err != nil {
			return nil, err
		}
		ip[i] = byte(b)
	}
	return ip, nil
}
