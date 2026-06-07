//go:build !linux && !openbsd && !freebsd && !netbsd

package apply

import (
	"fmt"
	"log/slog"
	"runtime"
)

// NewSystem on unsupported platforms (darwin / windows / illumos /
// dragonflybsd / solaris) always returns an error. The binary still
// compiles so go test / go vet on developers' macOS workstations work ;
// the moment someone tries to actually apply on macOS they get a clear
// message instead of a cryptic link failure.
func NewSystem(_ *slog.Logger) (System, error) {
	return nil, fmt.Errorf("weft-firstboot: unsupported OS %q (supported: linux, openbsd, freebsd, netbsd)", runtime.GOOS)
}
