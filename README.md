<p align="center"><img src="https://raw.githubusercontent.com/openweft/brand/main/social/openweft.png" alt="openweft" width="720"></p>

# weft-firstboot

Pure-Go cloud-init-lite for openweft VMs.

One binary, one config file, four supported guest OSes. Runs once at the
first boot of a freshly-installed VM to set hostname / create users /
install SSH keys / drop files / run post-boot scripts, then writes a
sentinel so subsequent boots short-circuit.

## Status

V0.1 — initial release. Tested cross-build matrix : Linux + OpenBSD +
FreeBSD + NetBSD on amd64 + arm64 (8 targets).

## What it does

```hcl
# /var/lib/weft-firstboot/user-data.hcl
hostname = "vmd-test"

user "openbsd" {
  ssh_authorized_keys = ["ssh-ed25519 AAAA... user@host"]
  groups              = ["operator"]
  doas                = true
  shell               = "/bin/ksh"
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
```

Apply :

```
weft-firstboot apply --config /var/lib/weft-firstboot/user-data.hcl
```

Or let the binary discover its user-data automatically — at first boot
it probes :

1. `--datasource <url>` (explicit, highest priority)
2. NoCloud cidata disk : a block device with FS label `cidata` /
   `CIDATA` holding `/user-data` (+ optional `/meta-data`)
3. NoCloud-NET : `http://<default-gateway>/user-data` (typically `http://10.0.2.2/user-data` on QEMU SLIRP / `http://192.168.x.1/user-data` on vmnet)

Format autodetect : a `#cloud-config` magic header dispatches the
cloud-config YAML legacy path ; anything else parses as HCL.

### The cidata disk is read, not mounted

The seed disk is decoded in pure Go. Each candidate device node is
opened **read-only**, its filesystem identified from its on-disk magic
signature by
[`go-filesystems/detect`](https://github.com/go-filesystems/detect), and
`/user-data` read straight out of the structures by
[`iso9660`](https://github.com/go-filesystems/iso9660) or
[`fat32`](https://github.com/go-filesystems/fat32). No `mount(2)`, no
`/sbin/mount_cd9660` fork, no root, and one implementation shared by
Linux and every BSD — only the list of device nodes to try stays
per-OS, because udev's `/dev/disk/by-label/` and the BSDs' bare disk
nodes are genuinely different things.

A **mount fallback** survives, and runs only when the direct read found
nothing on every candidate. It exists for seed shapes the pure-Go
drivers do not read yet:

| shape | direct read | mount fallback |
|---|---|---|
| iso9660 (Rock Ridge, Joliet, or plain ECMA-119) | yes | not reached |
| vfat / FAT32 (image ≥ ~33 MiB) | yes | not reached |
| vfat / **FAT12 or FAT16** (what `mkfs.vfat` picks below ~33 MiB) | **no** | yes |
| anything else udev labels `cidata` (ext4 seeds are rare but legal) | no | yes |

Which of the two served is recorded in the origin string, so `apply`'s
log line and the sentinel file say it plainly:

```
nocloud:/dev/sr0 (iso9660, direct)
nocloud:/tmp/weft-firstboot-cidata-123 (mount fallback)
```

If you see `mount fallback` on a guest, the seed is one of the shapes
above and the boot needed root to read it.

## What it does NOT do

By design, V0.x omits (as of V0.2) :

- Locale / NTP / keyboard / timezone modules
- Disk partition resize
- Datasources beyond NoCloud (no EC2/Azure/GCP/OpenStack/vSphere)
- Network configuration beyond DHCP

If you need any of these, file an issue — they're additive by design,
not redesigns.

## Config schema (HCL — preferred)

| Block | Required | Description |
|---|---|---|
| `hostname = "<str>"` | no | Set via OS-native mechanism (`hostnamectl`, `/etc/myname` + `hostname(1)`, `sysrc`, hand-edit of `/etc/rc.conf`) |
| `user "<name>" {...}` | no | Create user (or reconcile groups+keys if exists) |
| `write_file "<path>" {...}` | no | Atomic drop a file with mode + owner + group |
| `packages = ["<pkg>", ...]` | no | Install via OS pkg mgr (apt-get / dnf / yum / zypper / apk / pacman on Linux ; `pkg_add` on OpenBSD ; `pkg install` on FreeBSD ; `pkgin install` on NetBSD) |
| `runcmd = ["<sh>", ...]` | no | Sequential `sh -c` calls, halt on first non-zero exit |

`user "<name>" {}` accepts :

- `ssh_authorized_keys = ["<key>", ...]`
- `groups              = ["<g>", ...]`
- `sudo                = bool` (Linux ; grants `wheel`)
- `doas                = bool` (OpenBSD ; grants `wheel`)
- `shell               = "<path>"` (default `/bin/bash` on Linux, `/bin/ksh` on OpenBSD, `/bin/sh` on FreeBSD/NetBSD)
- `password_hash       = "<crypt>"` (empty → locked password, key-only)

`write_file "<path>" {}` accepts `content`, `mode` (octal, default `0644`),
`owner`, `group` (defaults `root` / `root` on Linux, `root` / `wheel` on
the BSDs).

## Config schema (cloud-config YAML — legacy)

Supported subset :

- `hostname` / `fqdn`
- `users[].name`, `users[].ssh_authorized_keys`, `users[].groups`,
  `users[].sudo`, `users[].shell`, `users[].passwd`
- `write_files[].path`, `.content`, `.permissions`, `.owner`
- `runcmd[]`, `bootcmd[]` (string or `[arg, arg, arg]` form)

Everything else is silently ignored.

## Idempotence

Every System primitive is idempotent. A second `weft-firstboot apply`
against the same Config + same host is a no-op, not an error. This
matters because :

- The sentinel may be lost (disk reset, VM image baked then re-cloned)
- An operator may manually re-run with `--force` for debugging
- Future runtime config reconciliation (planned) will share this
  apply path

## CLI

```
weft-firstboot apply [flags]
  --datasource <url>     explicit datasource (skip auto-discovery)
  --config <path>        read user-data from this local file
  --sentinel <path>      applied-marker path (default /var/lib/weft-firstboot/applied)
  --force                re-apply even if sentinel is present
  --dry-run              parse config + print plan ; do not mutate
  -v, --verbose          log at debug level

weft-firstboot parse --config <path>
  Parse and print the normalised Config without applying.

weft-firstboot version
  Print version / commit / build date.
```

## Building from source

```
go build ./cmd/weft-firstboot                    # host
GOOS=linux   GOARCH=arm64 go build ./cmd/...     # cross
GOOS=openbsd GOARCH=amd64 go build ./cmd/...
task cross-build                                  # all 8 targets to dist/
```

Pure-Go, `CGO_ENABLED=0` is required (and tested in CI).

## License

BSD 3-Clause — see LICENSE.
