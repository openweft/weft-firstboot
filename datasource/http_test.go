package datasource

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFromHTTP_HCLUserData : the typical openweft path -- HCL config
// served by an HTTP endpoint on a vmnet/SLIRP gateway.
func TestFromHTTP_HCLUserData(t *testing.T) {
	body := `
hostname = "vmd-test"
user "openbsd" {
  ssh_authorized_keys = ["ssh-ed25519 AAAA"]
}
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user-data" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	src, err := fromHTTP(srv.URL)
	if err != nil {
		t.Fatalf("fromHTTP: %v", err)
	}
	if src.Config.Hostname != "vmd-test" {
		t.Errorf("Hostname = %q ; want vmd-test", src.Config.Hostname)
	}
	if !strings.HasPrefix(src.Origin, "nocloud-net:http://") {
		t.Errorf("Origin = %q", src.Origin)
	}
}

// TestFromHTTP_CloudConfigUserData : the legacy path -- YAML user-data
// with the magic header.
func TestFromHTTP_CloudConfigUserData(t *testing.T) {
	body := `#cloud-config
hostname: legacy-host
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	src, err := fromHTTP(srv.URL + "/user-data")
	if err != nil {
		t.Fatalf("fromHTTP: %v", err)
	}
	if src.Config.Hostname != "legacy-host" {
		t.Errorf("Hostname = %q", src.Config.Hostname)
	}
}

// TestFromHTTP_404 : 404 maps to ErrNotFound so the caller can try
// the next datasource probe.
func TestFromHTTP_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer srv.Close()
	_, err := fromHTTP(srv.URL)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v ; want ErrNotFound", err)
	}
}

// TestFromHTTP_5xx : server-side errors are surfaced as-is (not
// ErrNotFound) because they indicate a real provisioning problem
// the operator must investigate, not "no datasource here".
func TestFromHTTP_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := fromHTTP(srv.URL)
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("err should NOT be ErrNotFound on 5xx ; got %v", err)
	}
}

// TestFromHTTP_NetworkUnreachable : connection refused maps to ErrNotFound.
func TestFromHTTP_NetworkUnreachable(t *testing.T) {
	// Pick a port that's almost certainly not listening : bind one and
	// release it so the next connect attempt fails fast on the same port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	_, err = fromHTTP("http://" + addr)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v ; want ErrNotFound on connection refused", err)
	}
}

// TestDiscoverOverride : an explicit override URL skips disk + auto-gateway.
func TestDiscoverOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`hostname = "explicit"`))
	}))
	defer srv.Close()

	src, err := Discover(srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if src.Config.Hostname != "explicit" {
		t.Errorf("Hostname = %q", src.Config.Hostname)
	}
}
