package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/pki"
)

// runPKI implements the operator CA workflow (docs/08 §TLS runbook):
//
//	fass-gateway pki init          --dir /etc/fass/pki/ca
//	fass-gateway pki issue-server  --ca-dir ... --dir ... --dns agent-1 --ip 10.0.0.11
//	fass-gateway pki issue-client  --ca-dir ... --dir ... --identity gateway-1
//	fass-gateway pki inspect       --cert /etc/fass/pki/agent/tls.crt
//
// Standard library crypto only; the CA key is written 0600 and is never needed
// at runtime by agents or gateways.
func runPKI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fass-gateway pki <init|issue-server|issue-client|inspect> [flags]")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
		dir := fs.String("dir", "", "CA output directory (ca.crt, ca.key)")
		cn := fs.String("cn", "fass-cluster-ca", "CA common name")
		org := fs.String("org", "FASS", "CA organization")
		ttl := fs.Duration("ttl", pki.DefaultCATTL, "CA lifetime")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *dir == "" {
			return fmt.Errorf("--dir is required")
		}
		ca, err := pki.InitCA(*dir, pki.CAOptions{CommonName: *cn, Organization: *org, TTL: *ttl})
		if err != nil {
			return err
		}
		fmt.Printf("CA created\n  cert: %s\n  key:  %s (0600; keep offline, not needed at runtime)\n  fingerprint: %s\n  expires: %s\n",
			ca.CertFile, ca.KeyFile, pki.Fingerprint(ca.Cert), ca.Cert.NotAfter.UTC().Format(time.RFC3339))
		return nil

	case "issue-server":
		fs := flag.NewFlagSet("pki issue-server", flag.ContinueOnError)
		caDir := fs.String("ca-dir", "", "directory containing ca.crt/ca.key")
		dir := fs.String("dir", "", "output directory (tls.crt, tls.key)")
		ttl := fs.Duration("ttl", pki.DefaultCertTTL, "certificate lifetime")
		cn := fs.String("cn", "", "common name (defaults to the first DNS name or IP)")
		var dns multiFlag
		var ips multiFlag
		fs.Var(&dns, "dns", "DNS SAN (repeatable)")
		fs.Var(&ips, "ip", "IP SAN (repeatable)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *caDir == "" || *dir == "" {
			return fmt.Errorf("--ca-dir and --dir are required")
		}
		ca, err := pki.LoadCA(filepath.Join(*caDir, pki.CAFile), filepath.Join(*caDir, pki.CAKeyFile))
		if err != nil {
			return err
		}
		dnsNames := []string(dns)
		if *cn != "" {
			dnsNames = append([]string{*cn}, dnsNames...)
		}
		ipList := make([]net.IP, 0, len(ips))
		for _, raw := range ips {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				return fmt.Errorf("invalid --ip %q", raw)
			}
			ipList = append(ipList, ip)
		}
		if len(dnsNames) == 0 && len(ipList) == 0 {
			return fmt.Errorf("at least one --dns or --ip SAN is required")
		}
		files, err := ca.IssueServer(dnsNames, ipList, *ttl, *dir)
		if err != nil {
			return err
		}
		return printIssued(files)

	case "issue-client":
		fs := flag.NewFlagSet("pki issue-client", flag.ContinueOnError)
		caDir := fs.String("ca-dir", "", "directory containing ca.crt/ca.key")
		dir := fs.String("dir", "", "output directory (tls.crt, tls.key)")
		identity := fs.String("identity", "", "component identity (certificate CN)")
		ttl := fs.Duration("ttl", pki.DefaultCertTTL, "certificate lifetime")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *caDir == "" || *dir == "" || *identity == "" {
			return fmt.Errorf("--ca-dir, --dir and --identity are required")
		}
		ca, err := pki.LoadCA(filepath.Join(*caDir, pki.CAFile), filepath.Join(*caDir, pki.CAKeyFile))
		if err != nil {
			return err
		}
		files, err := ca.IssueClient(*identity, *ttl, *dir)
		if err != nil {
			return err
		}
		return printIssued(files)

	case "inspect":
		fs := flag.NewFlagSet("pki inspect", flag.ContinueOnError)
		certFile := fs.String("cert", "", "certificate file")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *certFile == "" {
			return fmt.Errorf("--cert is required")
		}
		body, err := os.ReadFile(*certFile)
		if err != nil {
			return err
		}
		cert, err := pki.ParseCertificate(body)
		if err != nil {
			return err
		}
		fmt.Printf("subject:     %s\nissuer:      %s\nDNS SANs:    %v\nIP SANs:     %v\nfingerprint: %s\nexpires:     %s (renew after %s)\n",
			cert.Subject, cert.Issuer, cert.DNSNames, cert.IPAddresses, pki.Fingerprint(cert),
			cert.NotAfter.UTC().Format(time.RFC3339), cert.NotBefore.UTC().Add(cert.NotAfter.Sub(cert.NotBefore)*2/3).Format(time.RFC3339))
		return nil
	}
	return fmt.Errorf("unknown pki command %q (want init|issue-server|issue-client|inspect)", cmd)
}

func printIssued(files pki.CertFiles) error {
	body, err := os.ReadFile(files.CertFile)
	if err != nil {
		return err
	}
	cert, err := pki.ParseCertificate(body)
	if err != nil {
		return err
	}
	window, err := pki.RenewalWindow(body)
	if err != nil {
		return err
	}
	fmt.Printf("certificate issued\n  cert: %s\n  key:  %s (0600)\n  ca:   %s\n  fingerprint: %s\n  expires: %s\n  renew after: %s\n",
		files.CertFile, files.KeyFile, files.CAFile, pki.Fingerprint(cert),
		cert.NotAfter.UTC().Format(time.RFC3339), time.Until(cert.NotAfter.Add(-window)).Round(time.Hour))
	slog.Debug("certificate issued", "cert", files.CertFile)
	return nil
}
