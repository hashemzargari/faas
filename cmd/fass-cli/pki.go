package main

// Offline certificate helpers for operators. The same commands live under
// `fass-gateway pki` for compatibility, but issuing coordinator/agent
// certificates from the gateway binary was a UX wart: the gateway is not part
// of cluster bootstrap, so the neutral CLI command is the documented one.

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/pki"
)

// repeatedString is a flag.Value for repeatable --dns/--ip flags.
type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, ",") }

func (r *repeatedString) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("empty value")
	}
	*r = append(*r, strings.TrimSpace(v))
	return nil
}

func runPKI(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usagef("usage: fass pki <init|issue-server|issue-client|inspect> [flags] (see `fass pki --help`)")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		printPKIUsage(stdout)
		return nil
	case "init":
		fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		dir := fs.String("dir", "", "CA output directory (ca.crt, ca.key)")
		cn := fs.String("cn", "fass-cluster-ca", "CA common name")
		org := fs.String("org", "FASS", "CA organization")
		ttl := fs.Duration("ttl", pki.DefaultCATTL, "CA lifetime")
		if err := fs.Parse(rest); err != nil {
			return pkiFlagError(err)
		}
		if *dir == "" {
			return usagef("pki init: --dir is required")
		}
		ca, err := pki.InitCA(*dir, pki.CAOptions{CommonName: *cn, Organization: *org, TTL: *ttl})
		if err != nil {
			return usagef("pki init: %v", err)
		}
		fmt.Fprintf(stdout, "CA created\n  cert: %s\n  key:  %s (0600; keep offline, not needed at runtime)\n  fingerprint: %s\n  expires: %s\n",
			ca.CertFile, ca.KeyFile, pki.Fingerprint(ca.Cert), ca.Cert.NotAfter.UTC().Format(time.RFC3339))
		return nil

	case "issue-server":
		fs := flag.NewFlagSet("pki issue-server", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		caDir := fs.String("ca-dir", "", "directory containing ca.crt/ca.key")
		dir := fs.String("dir", "", "output directory (tls.crt, tls.key)")
		ttl := fs.Duration("ttl", pki.DefaultCertTTL, "certificate lifetime")
		cn := fs.String("cn", "", "common name (defaults to the first DNS name or IP)")
		var dns, ips repeatedString
		fs.Var(&dns, "dns", "DNS SAN (repeatable)")
		fs.Var(&ips, "ip", "IP SAN (repeatable)")
		if err := fs.Parse(rest); err != nil {
			return pkiFlagError(err)
		}
		if *caDir == "" || *dir == "" {
			return usagef("pki issue-server: --ca-dir and --dir are required")
		}
		ca, err := pki.LoadCA(filepath.Join(*caDir, pki.CAFile), filepath.Join(*caDir, pki.CAKeyFile))
		if err != nil {
			return usagef("pki issue-server: %v", err)
		}
		dnsNames := []string(dns)
		if *cn != "" {
			dnsNames = append([]string{*cn}, dnsNames...)
		}
		ipList := make([]net.IP, 0, len(ips))
		for _, raw := range ips {
			ip := net.ParseIP(raw)
			if ip == nil {
				return usagef("pki issue-server: invalid --ip %q", raw)
			}
			ipList = append(ipList, ip)
		}
		if len(dnsNames) == 0 && len(ipList) == 0 {
			return usagef("pki issue-server: at least one --dns or --ip SAN is required (peers verify the name they dial)")
		}
		files, err := ca.IssueServer(dnsNames, ipList, *ttl, *dir)
		if err != nil {
			return usagef("pki issue-server: %v", err)
		}
		return pkiPrintIssued(stdout, files)

	case "issue-client":
		fs := flag.NewFlagSet("pki issue-client", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		caDir := fs.String("ca-dir", "", "directory containing ca.crt/ca.key")
		dir := fs.String("dir", "", "output directory (tls.crt, tls.key)")
		identity := fs.String("identity", "", "component identity (certificate CN)")
		ttl := fs.Duration("ttl", pki.DefaultCertTTL, "certificate lifetime")
		if err := fs.Parse(rest); err != nil {
			return pkiFlagError(err)
		}
		if *caDir == "" || *dir == "" || *identity == "" {
			return usagef("pki issue-client: --ca-dir, --dir and --identity are required")
		}
		ca, err := pki.LoadCA(filepath.Join(*caDir, pki.CAFile), filepath.Join(*caDir, pki.CAKeyFile))
		if err != nil {
			return usagef("pki issue-client: %v", err)
		}
		files, err := ca.IssueClient(*identity, *ttl, *dir)
		if err != nil {
			return usagef("pki issue-client: %v", err)
		}
		return pkiPrintIssued(stdout, files)

	case "inspect":
		fs := flag.NewFlagSet("pki inspect", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		certFile := fs.String("cert", "", "certificate file")
		if err := fs.Parse(rest); err != nil {
			return pkiFlagError(err)
		}
		if *certFile == "" {
			return usagef("pki inspect: --cert is required")
		}
		body, err := os.ReadFile(*certFile)
		if err != nil {
			return usagef("pki inspect: %v", err)
		}
		cert, err := pki.ParseCertificate(body)
		if err != nil {
			return usagef("pki inspect: %v", err)
		}
		fmt.Fprintf(stdout, "subject:     %s\nissuer:      %s\nDNS SANs:    %v\nIP SANs:     %v\nfingerprint: %s\nexpires:     %s (renew after %s)\n",
			cert.Subject, cert.Issuer, cert.DNSNames, cert.IPAddresses, pki.Fingerprint(cert),
			cert.NotAfter.UTC().Format(time.RFC3339), cert.NotBefore.UTC().Add(cert.NotAfter.Sub(cert.NotBefore)*2/3).Format(time.RFC3339))
		return nil

	default:
		return usagef("unknown pki command %q (want init|issue-server|issue-client|inspect)", cmd)
	}
}

func pkiFlagError(err error) error {
	if err == flag.ErrHelp {
		return usagef("usage: fass pki <init|issue-server|issue-client|inspect> [flags]")
	}
	return usagef("%v", err)
}

func pkiPrintIssued(stdout io.Writer, files pki.CertFiles) error {
	body, err := os.ReadFile(files.CertFile)
	if err != nil {
		return usagef("pki: read issued certificate: %v", err)
	}
	cert, err := pki.ParseCertificate(body)
	if err != nil {
		return usagef("pki: parse issued certificate: %v", err)
	}
	window, err := pki.RenewalWindow(body)
	if err != nil {
		return usagef("pki: renewal window: %v", err)
	}
	fmt.Fprintf(stdout, "certificate issued\n  cert: %s\n  key:  %s (0600)\n  ca:   %s\n  fingerprint: %s\n  expires: %s\n  renew after: %s\n",
		files.CertFile, files.KeyFile, files.CAFile, pki.Fingerprint(cert),
		cert.NotAfter.UTC().Format(time.RFC3339), time.Until(cert.NotAfter.Add(-window)).Round(time.Hour))
	return nil
}

func printPKIUsage(w io.Writer) {
	fmt.Fprint(w, `fass pki — issue and inspect FASS certificates (offline; pure Go crypto)

The CA private key never belongs on a FASS host. Run these on an operator
workstation, distribute only ca.crt, and mount cert/key from existing Secrets
(Kubernetes) or /etc/fass/tls (systemd).

Usage:
  fass pki init          --dir ./pki/ca [--cn fass-cluster-ca] [--org FASS] [--ttl 8760h]
  fass pki issue-server  --ca-dir ./pki/ca --dir ./pki/coordinator \
                         --dns coordinator.example.internal [--dns ...] --ip 10.0.0.10 [--ip ...]
  fass pki issue-client  --ca-dir ./pki/ca --dir ./pki/console-client --identity console
  fass pki inspect       --cert ./pki/coordinator/tls.crt

SAN rule: every DNS name and IP a peer dials must be in the certificate
(coordinator URL hostname, gateway S3 name, each agent's announced hostname/IP).
`+"`fass-gateway pki ...`"+` remains available as a compatibility alias.
`)
}
