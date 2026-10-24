// Command fass is the FASS operator CLI: S3 client ergonomics (ls, cp, rm, mb,
// rb, presign) plus read-only cluster administration against the coordinator's
// HTTP API (health, cluster status, node ls, rc ls, repair status, gc status).
//
// The S3 side always goes through pkg/sdk so SigV4 is implemented in exactly one
// place. The admin side is plain HTTP+JSON because the coordinator's admin
// surface is not part of the S3 contract.
//
// Exit codes: 0 success, 1 user error (bad arguments, bad URL, missing
// credentials, S3 4xx), 2 service error (network, timeout, 5xx).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fass-storage/fass/pkg/sdk"
)

// version is stamped by -ldflags in release builds; the CLI reports it on
// `fass version` and in the User-Agent of admin requests.
var version = "0.1.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// globalOpts are the flags accepted before or after the subcommand.
type globalOpts struct {
	endpoint    string
	region      string
	accessKey   string
	secretKey   string
	coordinator string
	profile     string
	configPath  string
	timeout     time.Duration
	jsonOut     bool
	// endpointExplicit records that --endpoint/FASS_ENDPOINT/profile supplied
	// the gateway URL, so `fass health` knows whether to probe it.
	endpointExplicit bool
	quiet            bool
	help             bool
	showVersion      bool
}

func (g *globalOpts) register(fs *flag.FlagSet) {
	fs.StringVar(&g.endpoint, "endpoint", g.endpoint, "S3 gateway endpoint (env FASS_ENDPOINT)")
	fs.StringVar(&g.region, "region", g.region, "S3 region (env FASS_REGION)")
	fs.StringVar(&g.accessKey, "access-key", g.accessKey, "access key id (env FASS_ACCESS_KEY_ID)")
	fs.StringVar(&g.secretKey, "secret", g.secretKey, "secret access key (env FASS_SECRET_ACCESS_KEY)")
	fs.StringVar(&g.secretKey, "secret-key", g.secretKey, "alias for --secret")
	fs.StringVar(&g.coordinator, "coordinator", g.coordinator, "coordinator base URL (env FASS_COORDINATOR_URL)")
	fs.StringVar(&g.profile, "profile", g.profile, "config profile in ~/.fass/config (env FASS_PROFILE)")
	fs.StringVar(&g.configPath, "config", g.configPath, "config file path (env FASS_CONFIG)")
	fs.DurationVar(&g.timeout, "timeout", g.timeout, "per-request timeout")
	fs.BoolVar(&g.jsonOut, "json", g.jsonOut, "machine-readable JSON output")
	fs.BoolVar(&g.quiet, "quiet", g.quiet, "suppress progress lines")
	fs.BoolVar(&g.help, "help", g.help, "show help")
	fs.BoolVar(&g.help, "h", g.help, "show help")
	fs.BoolVar(&g.showVersion, "version", g.showVersion, "print version and exit")
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	err := dispatch(ctx, args, stdout, stderr)
	if err == nil {
		return 0
	}
	code := classifyError(err)
	if code != 0 {
		fmt.Fprintf(stderr, "fass: %v\n", err)
	}
	return code
}

// dispatch finds the subcommand, resolves configuration defaults, and runs it.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	idx, err := findCommand(args)
	if err != nil {
		return err
	}
	if idx < 0 {
		// No subcommand: --version wins, otherwise usage.
		var g globalOpts
		fs := flag.NewFlagSet("fass", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		g.register(fs)
		if err := fs.Parse(args); err != nil {
			return usagef("%v", err)
		}
		if g.showVersion {
			fmt.Fprintf(stdout, "fass %s\n", version)
			return nil
		}
		printUsage(stdout)
		if g.help {
			return nil
		}
		return usagef("no command given")
	}

	cmd, cmdArgs := args[idx], args[idx+1:]
	preArgs := args[:idx]

	profile, configPath, err := prescanConfigFlags(preArgs, cmdArgs)
	if err != nil {
		return err
	}
	settings, err := resolveSettings(profile, configPath)
	if err != nil {
		return err
	}

	g := &globalOpts{
		endpoint:         settings.endpoint,
		region:           settings.region,
		accessKey:        settings.accessKey,
		secretKey:        settings.secretKey,
		coordinator:      settings.coordinator,
		profile:          settings.profileName,
		configPath:       settings.configPath,
		timeout:          settings.timeout,
		endpointExplicit: settings.endpointExplicit,
	}
	// Global flags given before the subcommand are parsed first so that command
	// flag descriptions share the same variables; flags after the subcommand win.
	preFS := flag.NewFlagSet("fass", flag.ContinueOnError)
	preFS.SetOutput(io.Discard)
	g.register(preFS)
	if err := preFS.Parse(preArgs); err != nil {
		return usagef("%v", err)
	}
	if g.showVersion {
		fmt.Fprintf(stdout, "fass %s\n", version)
		return nil
	}

	switch cmd {
	case "help":
		printUsage(stdout)
		return nil
	case "version":
		fmt.Fprintf(stdout, "fass %s\n", version)
		return nil
	case "ls":
		pos, err := parseCommandFlags(g, "ls", cmdArgs, stderr, func(fs *flag.FlagSet) {})
		if err != nil {
			return err
		}
		if g.help {
			printCommandUsage(stdout, "ls")
			return nil
		}
		return runLS(ctx, g, pos, stdout)
	case "cp":
		var recursive bool
		var contentType string
		pos, err := parseCommandFlags(g, "cp", cmdArgs, stderr, func(fs *flag.FlagSet) {
			fs.BoolVar(&recursive, "recursive", false, "copy directories recursively")
			fs.BoolVar(&recursive, "r", false, "alias for --recursive")
			fs.StringVar(&contentType, "content-type", "", "Content-Type for uploads (default: inferred from the file extension)")
		})
		if err != nil {
			return err
		}
		if g.help {
			printCommandUsage(stdout, "cp")
			return nil
		}
		return runCP(ctx, g, pos, recursive, contentType, stdout, stderr)
	case "rm":
		var recursive bool
		pos, err := parseCommandFlags(g, "rm", cmdArgs, stderr, func(fs *flag.FlagSet) {
			fs.BoolVar(&recursive, "recursive", false, "delete every object under a prefix")
			fs.BoolVar(&recursive, "r", false, "alias for --recursive")
		})
		if err != nil {
			return err
		}
		if g.help {
			printCommandUsage(stdout, "rm")
			return nil
		}
		return runRM(ctx, g, pos, recursive, stdout)
	case "mb", "rb":
		pos, err := parseCommandFlags(g, cmd, cmdArgs, stderr, func(fs *flag.FlagSet) {})
		if err != nil {
			return err
		}
		if g.help {
			printCommandUsage(stdout, cmd)
			return nil
		}
		return runBucket(ctx, g, cmd, pos, stdout)
	case "presign":
		var ttl time.Duration
		pos, err := parseCommandFlags(g, "presign", cmdArgs, stderr, func(fs *flag.FlagSet) {
			fs.DurationVar(&ttl, "ttl", 15*time.Minute, "URL validity period (max 7 days)")
		})
		if err != nil {
			return err
		}
		if g.help {
			printCommandUsage(stdout, "presign")
			return nil
		}
		return runPresign(ctx, g, pos, ttl, stdout)
	case "health":
		pos, err := parseCommandFlags(g, "health", cmdArgs, stderr, func(fs *flag.FlagSet) {})
		if err != nil {
			return err
		}
		if g.help {
			printCommandUsage(stdout, "health")
			return nil
		}
		return runHealth(ctx, g, pos, stdout)
	case "cluster":
		return runCluster(ctx, g, cmdArgs, stdout, stderr)
	case "node":
		return runNode(ctx, g, cmdArgs, stdout, stderr)
	case "rc":
		return runRC(ctx, g, cmdArgs, stdout, stderr)
	case "repair":
		return runRepair(ctx, g, cmdArgs, stdout, stderr)
	case "gc":
		return runGC(ctx, g, cmdArgs, stdout, stderr)
	case "pki":
		if g.help {
			printPKIUsage(stdout)
			return nil
		}
		return runPKI(cmdArgs, stdout)
	default:
		return usagef("unknown command %q (try `fass help`)", cmd)
	}
}

// parseCommandFlags registers the global flags plus command-specific ones and
// parses cmdArgs, allowing flags before, between and after positional arguments.
func parseCommandFlags(g *globalOpts, name string, args []string, stderr io.Writer, register func(*flag.FlagSet)) ([]string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.register(fs)
	if register != nil {
		register(fs)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, usagef("%v", err)
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "endpoint" {
			g.endpointExplicit = true
		}
	})
	_ = stderr // reserved for future command-specific diagnostics
	return pos, nil
}

// parseInterspersed parses flags mixed with positional arguments. Go's flag
// package stops at the first positional; operators expect `fass cp src dst -r`.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		if strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		f := fs.Lookup(name)
		if f == nil {
			// Let fs.Parse produce the canonical "flag provided but not defined".
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return pos, fs.Parse(flagArgs)
}

// findCommand returns the index of the first positional argument (the
// subcommand) or -1 when there is none. Known global flags with values are
// skipped so `fass --profile prod ls` finds `ls`.
func findCommand(args []string) (int, error) {
	valueFlags := map[string]bool{
		"endpoint": true, "region": true, "access-key": true, "secret": true,
		"secret-key": true, "coordinator": true, "profile": true, "config": true,
		"timeout": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return i + 1, nil
			}
			return -1, nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return i, nil
		}
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
		}
	}
	return -1, nil
}

// prescanConfigFlags extracts --profile/--config without parsing anything else,
// because the config profile determines the defaults for every other flag.
func prescanConfigFlags(parts ...[]string) (profile, configPath string, err error) {
	for _, args := range parts {
		for i := 0; i < len(args); i++ {
			a := args[i]
			if !strings.HasPrefix(a, "-") {
				continue
			}
			name := strings.TrimLeft(a, "-")
			val := ""
			hasVal := false
			if j := strings.IndexByte(name, '='); j >= 0 {
				name, val, hasVal = name[:j], name[j+1:], true
			}
			switch name {
			case "profile", "config":
				if !hasVal {
					if i+1 >= len(args) {
						return "", "", usagef("--%s requires a value", name)
					}
					i++
					val = args[i]
				}
				if name == "profile" {
					profile = val
				} else {
					configPath = val
				}
			}
		}
	}
	return profile, configPath, nil
}

// classifyError maps errors to the documented exit codes.
func classifyError(err error) int {
	var u *userError
	if errors.As(err, &u) {
		return 1
	}
	var s *serviceError
	if errors.As(err, &s) {
		return 2
	}
	var se *sdk.Error
	if errors.As(err, &se) {
		if se.StatusCode >= 500 {
			return 2
		}
		return 1
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 2
	}
	var nerr interface{ Timeout() bool }
	if errors.As(err, &nerr) && nerr.Timeout() {
		return 2
	}
	return 2
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

// userError is a usage/credential problem: exit 1.
type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &userError{msg: fmt.Sprintf(format, args...)}
}

// serviceError is an unreachable/failing service: exit 2.
type serviceError struct {
	msg string
	err error
}

func (e *serviceError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}
	return e.msg
}

func (e *serviceError) Unwrap() error { return e.err }

func servicef(err error, format string, args ...any) error {
	return &serviceError{msg: fmt.Sprintf(format, args...), err: err}
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

func printUsage(w io.Writer) {
	fmt.Fprint(w, `fass — FASS operator CLI

Usage:
  fass [global flags] <command> [flags] [args]

S3 commands (pkg/sdk SigV4):
  ls [s3://bucket[/prefix]]            list buckets, or objects under a prefix
  cp <src> <dst>                       copy local↔s3 or s3↔s3 (--recursive)
  rm s3://bucket/key                   delete an object (--recursive for prefixes)
  mb <bucket>                          create a bucket
  rb <bucket>                          delete an empty bucket
  presign s3://bucket/key [--ttl 15m]  print a presigned GET URL

Coordinator admin commands (HTTP+JSON):
  health                               coordinator/gateway health
  cluster status                       agents, nexuses, nodes, rings, RC ratio
  node ls                              nodes with their agents and states
  rc ls                                redundancy classes and their overhead
  repair status                        repair/risk summary (derived from topology)
  gc status                            deletion-GC counters from /metrics

Certificates (offline; neutral CLI):
  pki init                            create the cluster CA (keep ca.key offline)
  pki issue-server                    issue a listener certificate (repeatable --dns/--ip)
  pki issue-client                    issue a clientAuth identity
  pki inspect                         print subject/SANs/fingerprint/expiry

Global flags:
  --endpoint URL        S3 gateway (default http://127.0.0.1:8080)
  --region REGION       default eu-west-1
  --access-key ID       or FASS_ACCESS_KEY_ID / AWS_ACCESS_KEY_ID
  --secret KEY          or FASS_SECRET_ACCESS_KEY / AWS_SECRET_ACCESS_KEY
  --coordinator URL     coordinator base (default http://127.0.0.1:7000)
  --profile NAME        profile in ~/.fass/config (default "default")
  --config PATH         config file (default ~/.fass/config, env FASS_CONFIG)
  --timeout DURATION    per-request timeout (default 60s)
  --json                machine-readable output
  --quiet               suppress progress lines

Exit codes: 0 success, 1 user error, 2 service error.
`)
}

func printCommandUsage(w io.Writer, cmd string) {
	switch cmd {
	case "ls":
		fmt.Fprintln(w, "usage: fass ls [--json] [s3://bucket[/prefix]]")
	case "cp":
		fmt.Fprintln(w, "usage: fass cp [-r|--recursive] [--content-type TYPE] <src> <dst>")
		fmt.Fprintln(w, "  src/dst: local path or s3://bucket/key; exactly one side must be S3")
	case "rm":
		fmt.Fprintln(w, "usage: fass rm [-r|--recursive] [--json] s3://bucket/key")
	case "mb", "rb":
		fmt.Fprintf(w, "usage: fass %s [--json] <bucket>\n", cmd)
	case "presign":
		fmt.Fprintln(w, "usage: fass presign [--ttl 15m] [--json] s3://bucket/key")
	case "health":
		fmt.Fprintln(w, "usage: fass health [--json] [--endpoint URL] [--coordinator URL]")
	case "cluster":
		fmt.Fprintln(w, "usage: fass cluster status [--json]")
	case "node":
		fmt.Fprintln(w, "usage: fass node ls [--json]")
	case "rc":
		fmt.Fprintln(w, "usage: fass rc ls [--json]")
	case "repair":
		fmt.Fprintln(w, "usage: fass repair status [--json]")
	case "gc":
		fmt.Fprintln(w, "usage: fass gc status [--json]")
	case "pki":
		printPKIUsage(w)
	default:
		fmt.Fprintf(w, "usage: fass %s ...\n", cmd)
	}
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// s3Client builds an SDK client, refusing to run without credentials.
func (g *globalOpts) s3Client() (*sdk.Client, error) {
	if g.accessKey == "" || g.secretKey == "" {
		return nil, usagef("missing S3 credentials: set --access-key/--secret, FASS_ACCESS_KEY_ID/FASS_SECRET_ACCESS_KEY, or a profile in ~/.fass/config")
	}
	hc := &http.Client{Timeout: g.timeout}
	c, err := sdk.New(g.endpoint, g.region, g.accessKey, g.secretKey, sdk.WithHTTPClient(hc))
	if err != nil {
		return nil, usagef("%v", err)
	}
	return c, nil
}

// defaultConfigPath is ~/.fass/config, or empty when HOME is unavailable.
func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".fass", "config")
}
