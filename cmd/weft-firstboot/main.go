// Command weft-firstboot is the openweft cloud-init-lite. One binary,
// one config file (HCL preferred, cloud-config YAML legacy), four
// supported guest OSes (linux, openbsd, freebsd, netbsd).
//
// At first boot of a freshly-installed VM, weft-firstboot :
//
//  1. Discovers the user-data datasource (CLI override, NoCloud cidata
//     disk, NoCloud-NET via the default gateway HTTP).
//  2. Parses it as HCL or cloud-config YAML (autodetect by magic header).
//  3. Applies hostname / users / SSH keys / write_files / runcmds in
//     that order via the OS-native primitives.
//  4. Writes a sentinel at /var/lib/weft-firstboot/applied so the next
//     boot short-circuits the whole flow (idempotent by construction).
//
// Unlike full cloud-init, weft-firstboot deliberately does NOT do :
// package install, locale / NTP / keyboard modules, disk resize,
// arbitrary metadata sources (EC2/Azure/GCP/OpenStack/vSphere). Those
// are out of scope for V0.1.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/openweft/weft-firstboot/apply"
	"github.com/openweft/weft-firstboot/datasource"
)

// Build metadata, injected via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:          "weft-firstboot",
		Short:        "openweft cloud-init-lite for Linux + *BSD VMs",
		Long:         "weft-firstboot discovers user-data (NoCloud disk or HTTP), parses HCL\nor cloud-config YAML, and applies hostname / users / SSH keys /\nwrite_files / runcmds on the running host. Runs once per VM lifetime ;\nsubsequent boots short-circuit via a sentinel file.",
		SilenceUsage: true,
	}
	root.AddCommand(versionCmd(), applyCmd(), parseCmd())
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "weft-firstboot %s (commit %s, built %s)\n", version, commit, date)
			return err
		},
	}
}

type applyFlags struct {
	datasourceURL string
	configFile    string
	sentinelPath  string
	force         bool
	dryRun        bool
	verbose       bool
}

func applyCmd() *cobra.Command {
	var f applyFlags
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Discover user-data and apply it to the running host",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runApply(f)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&f.datasourceURL, "datasource", "", "explicit datasource URL (skip auto-discovery)")
	flags.StringVar(&f.configFile, "config", "", "read user-data from this local file (skip datasource discovery)")
	flags.StringVar(&f.sentinelPath, "sentinel", "/var/lib/weft-firstboot/applied", "path to the applied-marker file")
	flags.BoolVar(&f.force, "force", false, "re-apply even if the sentinel file is present")
	flags.BoolVar(&f.dryRun, "dry-run", false, "parse the config and print the apply plan ; do not mutate the host")
	flags.BoolVarP(&f.verbose, "verbose", "v", false, "log at debug level")
	return cmd
}

func parseCmd() *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:     "parse",
		Aliases: []string{"validate"},
		Short:   "Parse a user-data file and print the normalised Config",
		Long:    "Parses the given file as HCL (default) or cloud-config YAML (when the\nbody starts with `#cloud-config`) and prints the resulting Config.\nUse this to validate a user-data file before staging it on the HTTP\nserver or baking it into a cidata disk.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configFile == "" {
				return fmt.Errorf("--config <path> is required")
			}
			raw, err := os.ReadFile(configFile)
			if err != nil {
				return err
			}
			cfg, err := datasource.Parse(raw)
			if err != nil {
				return fmt.Errorf("parse %s: %w", configFile, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%+v\n", cfg)
			return nil
		},
	}
	cmd.Flags().StringVar(&configFile, "config", "", "user-data file to parse (HCL or cloud-config YAML)")
	return cmd
}

func runApply(f applyFlags) error {
	level := slog.LevelInfo
	if f.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if !f.force && sentinelPresent(f.sentinelPath) {
		log.Info("sentinel present ; skipping apply", "path", f.sentinelPath)
		return nil
	}

	var src datasource.Source
	if f.configFile != "" {
		raw, err := os.ReadFile(f.configFile)
		if err != nil {
			return fmt.Errorf("read --config %s: %w", f.configFile, err)
		}
		cfg, err := datasource.Parse(raw)
		if err != nil {
			return fmt.Errorf("parse %s: %w", f.configFile, err)
		}
		src = datasource.Source{
			Origin: "file:" + f.configFile,
			Raw:    raw,
			Config: cfg,
		}
		log.Info("loaded user-data from file", "path", f.configFile)
	} else {
		var err error
		src, err = datasource.Discover(f.datasourceURL)
		if err != nil {
			return fmt.Errorf("datasource discover: %w", err)
		}
		log.Info("loaded user-data from datasource", "origin", src.Origin, "bytes", len(src.Raw))
	}

	if f.dryRun {
		log.Info("dry-run : config parsed ; not applying")
		fmt.Printf("%+v\n", src.Config)
		return nil
	}

	sys, err := apply.NewSystem(log)
	if err != nil {
		return err
	}
	if err := apply.Apply(src.Config, sys, log); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	if err := writeSentinel(f.sentinelPath, src.Origin); err != nil {
		log.Warn("sentinel write failed (non-fatal)", "path", f.sentinelPath, "err", err)
	}
	log.Info("first-boot applied", "origin", src.Origin)
	return nil
}

// sentinelPresent is true when the marker file exists. Its content
// (origin URL + timestamp) is for human forensics, not state ; presence
// alone short-circuits re-apply on subsequent boots.
func sentinelPresent(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeSentinel(path, origin string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("applied=%s\norigin=%s\n", time.Now().UTC().Format(time.RFC3339), origin)
	return os.WriteFile(path, []byte(content), 0o644)
}
