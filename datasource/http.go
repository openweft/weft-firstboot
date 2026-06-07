package datasource

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// fromHTTP fetches user-data from the given URL. The URL is expected to be
// the BASE URL ; we append "/user-data" if absent (cloud-init convention).
//
// Network errors (no route, DNS fail, connection refused, 404 are all
// surfaced as ErrNotFound so the higher Discover can try the next probe.
// Anything else (malformed body, HTTP 5xx) is surfaced as-is so a broken
// HTTP server doesn't silently look like "datasource not found".
func fromHTTP(baseURL string) (Source, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return Source{}, fmt.Errorf("parse url %q: %w", baseURL, err)
	}
	if !strings.HasSuffix(u.Path, "/user-data") {
		// Append, preserving trailing slash semantics.
		if strings.HasSuffix(u.Path, "/") {
			u.Path += "user-data"
		} else {
			u.Path += "/user-data"
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		// Network-level errors map to NotFound so the next probe runs.
		return Source{}, fmt.Errorf("%w: %s: %v", ErrNotFound, u, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound:
		return Source{}, fmt.Errorf("%w: %s: %s", ErrNotFound, u, resp.Status)
	default:
		// 5xx, 401, 403 — these are real errors worth surfacing.
		return Source{}, fmt.Errorf("http %s: %s", u, resp.Status)
	}
	raw, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, 1<<20))
	if err != nil {
		return Source{}, fmt.Errorf("read %s: %w", u, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Source{}, err
	}
	return Source{
		Origin: "nocloud-net:" + u.String(),
		Raw:    raw,
		Config: cfg,
	}, nil
}

// fromDefaultGatewayHTTP probes the host pointed at by the default IPv4
// route. cloud-init's NoCloud-NET datasource uses the DHCP-supplied
// next-server / SLIRP's 10.0.2.2 / vmnet's gateway as the URL host.
//
// We don't read the DHCP lease ourselves (too much DHCP-client surface
// to drag in) — we just walk the kernel routing table to find the
// default gateway. Works identically across Linux / *BSD via the
// "route get default" probe in defaultGateway_<os>.go.
func fromDefaultGatewayHTTP() (Source, error) {
	gw, err := defaultGateway()
	if err != nil {
		return Source{}, fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	if gw == nil {
		return Source{}, fmt.Errorf("%w: no default gateway", ErrNotFound)
	}
	// IPv6 literal needs brackets in URL hosts.
	host := gw.String()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	src, err := fromHTTP("http://" + host + "/user-data")
	if err != nil {
		return Source{}, err
	}
	return src, nil
}

// defaultGateway returns the IPv4 (or IPv6 if no v4) default gateway.
// Implementation differs per OS — see defaultgateway_*.go.
//
// As of V0.1 we only need an IPv4 gateway (every supported install
// flow uses IPv4 DHCP). We expose it as a variable so tests can stub.
var defaultGateway = func() (net.IP, error) {
	return nil, errors.New("defaultGateway: not implemented for this platform")
}
