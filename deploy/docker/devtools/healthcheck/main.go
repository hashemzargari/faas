// Command fass-dev-healthcheck is a tiny HTTP/TLS liveness probe for the
// distroless FASS image (which has no shell, curl or wget). It is used by the
// compose healthchecks and by the Helm chart's exec probes when a listener is
// TLS-only:
//
//	fass-dev-healthcheck http://127.0.0.1:7000/healthz
//	fass-dev-healthcheck -insecure https://127.0.0.1:7000/healthz
//	fass-dev-healthcheck -ca /etc/fass/tls/ca/ca.crt https://coordinator:7000/healthz
//
// -insecure only skips certificate verification for this local probe; it does
// not change any FASS component's security posture. Exit 0 on a 2xx response,
// 1 otherwise, 2 on usage error.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	fs := flag.NewFlagSet("fass-dev-healthcheck", flag.ContinueOnError)
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (local probe only)")
	caFile := fs.String("ca", "", "PEM CA bundle to verify the server certificate")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: fass-dev-healthcheck [-insecure] [-ca CA_PEM] URL")
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure} //nolint:gosec // probe-only opt-in
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: read CA: %v\n", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fmt.Fprintf(os.Stderr, "healthcheck: no certificates found in %s\n", *caFile)
			os.Exit(1)
		}
		tlsCfg.RootCAs = pool
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	resp, err := client.Get(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %d\n", fs.Arg(0), resp.StatusCode)
		os.Exit(1)
	}
}
