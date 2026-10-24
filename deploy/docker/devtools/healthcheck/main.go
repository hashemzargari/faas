// Command fass-dev-healthcheck is a tiny HTTP liveness probe for the distroless
// FASS image (which has no shell, curl or wget). Used by compose healthchecks.
//
//	fass-dev-healthcheck http://127.0.0.1:7000/healthz
//
// Exit 0 on a 2xx response, 1 otherwise, 2 on usage error.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fass-dev-healthcheck URL")
		os.Exit(2)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %d\n", os.Args[1], resp.StatusCode)
		os.Exit(1)
	}
}
