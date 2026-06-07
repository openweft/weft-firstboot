//go:build linux || openbsd || freebsd || netbsd

package apply

import (
	"fmt"
	"log/slog"
	"runtime"
)

// NewSystem returns the System impl for the running OS. The actual
// implementations live behind build tags in apply_<os>.go ; each
// defines osNewSystem(*slog.Logger) System and this factory dispatches
// via runtime.GOOS as a defensive check (the build tag above already
// guarantees the right impl is linked in).
//
// On unsupported platforms (darwin / windows / illumos / dragonflybsd /
// solaris), the binary doesn't link factory.go at all — see
// factory_unsupported.go which surfaces the error path. Tests on those
// platforms exercise memSystem directly.
func NewSystem(log *slog.Logger) (System, error) {
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd", "netbsd":
		return osNewSystem(log), nil
	default:
		return nil, fmt.Errorf("weft-firstboot: unsupported OS %q (supported: linux, openbsd, freebsd, netbsd)", runtime.GOOS)
	}
}
