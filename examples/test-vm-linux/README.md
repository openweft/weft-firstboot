# test-vm-linux

Reproducible QEMU/Ubuntu test VM driven by `weft-firstboot`. The Linux
pendant of [`weft-driver-vmd`'s
`Taskfile.test-vm.yml`](https://github.com/openweft/weft-driver-vmd/blob/main/Taskfile.test-vm.yml).

## Architecture

Both this example and the OpenBSD one ship the same kind of bootstrap
layer that just installs `weft-firstboot` and runs it once ; everything
substantive (hostname, users, SSH keys, packages, `runcmd`) lives in
the SAME HCL config the OpenBSD VM consumes. Cross-OS portability of
the format is the whole point.

| OS | Boot media | Bootstrap layer | First-boot trigger |
|---|---|---|---|
| OpenBSD | install ISO modified to `boot bsd.rd auto` | `install.conf` + `autoinstall.tail` | `/etc/rc.local` |
| Ubuntu | Cloud image qcow2 (pre-installed) | `cidata.iso` (NoCloud datasource) | `cloud-init runcmd` |

The cidata user-data is a five-line cloud-config :

```yaml
#cloud-config
runcmd:
  - [curl, -fsSL, -o, /usr/local/bin/weft-firstboot, http://10.0.2.2:8080/weft-firstboot]
  - [chmod, "0755", /usr/local/bin/weft-firstboot]
  - [/usr/local/bin/weft-firstboot, apply, --datasource, "http://10.0.2.2:8080/"]
```

That's it. From there `weft-firstboot apply` does the real work via
its HCL config, which is identical in shape to the OpenBSD one.

## Prerequisites

- macOS host with HVF (Apple Silicon or Intel Mac)
- `socket_vmnet` running : `brew install socket_vmnet && sudo brew services start socket_vmnet`
- `pkgx` for `qemu` + `xorriso` : `curl -fsS https://pkgx.sh | sh`
- `python3` (ships with macOS)
- `~/.ssh/id_ed25519.pub` or `id_rsa.pub`

## Lifecycle

```sh
task firstboot   # one-shot SLIRP boot ; cloud-init fires weft-firstboot
task up          # boot via vmnet for SSH (in another terminal)
task ssh         # SSH in via vmnet DHCP lease
task down        # ACPI shutdown via QMP (from another terminal)
task clean       # nuke disk + ISOs + downloaded image
```

## What's in the HCL config

See `Taskfile.yml`'s `user-data-hcl` task. The rendered config does :

- Set hostname `linux-test`
- Create `ubuntu` user with the host's SSH pubkey + passwordless sudo
- Drop `/etc/sudoers.d/90-ubuntu-nopasswd`
- Install `git`, `tmux`, `vim`, `build-essential` via apt-get
  (autodetected by weft-firstboot's `linux.PackageInstall`)
- Enable + start `ssh`

Edit the task or extract the HCL to a separate file to customise.
