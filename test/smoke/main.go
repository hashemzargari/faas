package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/fass-storage/fass/pkg/sdk"
)

const (
	objKey = "e2e/object.bin"
	objSz  = 14 << 20
)

func payload() []byte {
	b := make([]byte, objSz)
	rand.New(rand.NewSource(42)).Read(b)
	return b
}

func main() {
	mode := os.Args[1]
	c, err := sdk.New(os.Args[2], "eu-west-1", os.Args[3], os.Args[4])
	if err != nil {
		fmt.Println("client:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	switch mode {
	case "upload":
		name := fmt.Sprintf("smoke-%d", time.Now().UnixNano())
		if err := c.CreateBucket(ctx, name); err != nil {
			fmt.Println("CREATE_FAIL:", err)
			os.Exit(2)
		}
		etag, err := c.PutObject(ctx, name, objKey, bytes.NewReader(payload()), objSz, "application/octet-stream")
		if err != nil {
			fmt.Println("PUT_FAIL:", err)
			os.Exit(3)
		}
		fmt.Println("PUT_OK etag:", etag)
		fmt.Println("BUCKET=" + name)
	case "verify":
		name := os.Args[5]
		start := time.Now()
		rc, err := c.GetObject(ctx, name, objKey)
		if err != nil {
			fmt.Println("GET_FAIL:", err)
			os.Exit(4)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			fmt.Println("READ_FAIL:", err)
			os.Exit(5)
		}
		if !bytes.Equal(got, payload()) {
			fmt.Printf("CONTENT_MISMATCH got=%d want=%d\n", len(got), objSz)
			os.Exit(6)
		}
		fmt.Printf("GET_OK bytes=%d elapsed=%s\n", len(got), time.Since(start).Round(time.Millisecond))
		rrc, err := c.GetObjectRange(ctx, name, objKey, 1000, 1999)
		if err != nil {
			fmt.Println("RANGE_FAIL:", err)
			os.Exit(7)
		}
		rgot, _ := io.ReadAll(rrc)
		rrc.Close()
		if !bytes.Equal(rgot, payload()[1000:2000]) {
			fmt.Println("RANGE_MISMATCH")
			os.Exit(8)
		}
		fmt.Println("RANGE_OK")
		fmt.Println("VERIFY_PASS")
	}
}
