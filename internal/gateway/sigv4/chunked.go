package sigv4

import (
	"bufio"
	"crypto/hmac"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ChunkedOptions configures an aws-chunked payload reader.
type ChunkedOptions struct {
	// Kind is the x-amz-content-sha256 declaration of the request.
	Kind string
	// SeedSignature is the signature of the signed request; it starts the
	// chunk signature chain.
	SeedSignature string
	// SigningKey is the derived aws4_request signing key.
	SigningKey []byte
	// AmzDate is the request's x-amz-date value (ISO-8601 basic).
	AmzDate string
	// Scope is the request's credential scope.
	Scope Scope
	// MaxChunkBytes guards against absurd chunk declarations. Defaults to
	// 64 MiB.
	MaxChunkBytes int
}

// ChunkedReader decodes an aws-chunked request body, verifying each chunk's
// signature (for the STREAMING-AWS4-HMAC-SHA256-PAYLOAD schemes) and any signed
// trailers, and yielding the decoded payload bytes only.
//
// It is not safe for concurrent use.
type ChunkedReader struct {
	br   *bufio.Reader
	opts ChunkedOptions

	prevSig string
	chunk   []byte
	off     int
	done    bool
	err     error
	// finalChunkRead records that the terminating zero-length chunk has been
	// consumed (used for trailer verification).
	trailers map[string]string
	// decodedLen is the number of payload bytes yielded so far.
	decodedLen int64
}

// NewChunkedReader returns a reader for an aws-chunked body.
func NewChunkedReader(r io.Reader, opts ChunkedOptions) (*ChunkedReader, error) {
	switch opts.Kind {
	case PayloadStreaming, PayloadStreamingTrailer, PayloadUnsignedTrailer, PayloadUnsignedChunked:
	default:
		return nil, fmt.Errorf("%w: not an aws-chunked payload: %q", ErrMalformedAuth, opts.Kind)
	}
	if opts.MaxChunkBytes <= 0 {
		opts.MaxChunkBytes = 64 << 20
	}
	if opts.SeedSignature != "" {
		opts.SeedSignature = strings.ToLower(opts.SeedSignature)
	}
	return &ChunkedReader{
		br:      bufio.NewReaderSize(r, 64<<10),
		opts:    opts,
		prevSig: opts.SeedSignature,
	}, nil
}

// Read implements io.Reader over the decoded payload.
func (c *ChunkedReader) Read(p []byte) (int, error) {
	for {
		if c.err != nil {
			return 0, c.err
		}
		if c.off < len(c.chunk) {
			n := copy(p, c.chunk[c.off:])
			c.off += n
			c.decodedLen += int64(n)
			return n, nil
		}
		if c.done {
			return 0, io.EOF
		}
		if err := c.nextChunk(); err != nil {
			c.err = err
			return 0, err
		}
	}
}

// Trailers returns the trailer headers that followed the terminating chunk.
// It is only meaningful after Read has returned io.EOF.
func (c *ChunkedReader) Trailers() map[string]string {
	out := make(map[string]string, len(c.trailers))
	for k, v := range c.trailers {
		out[k] = v
	}
	return out
}

// DecodedLen reports how many payload bytes have been read.
func (c *ChunkedReader) DecodedLen() int64 { return c.decodedLen }

func (c *ChunkedReader) nextChunk() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	ext := ""
	sizePart := line
	if i := strings.IndexByte(line, ';'); i >= 0 {
		sizePart, ext = line[:i], line[i+1:]
	}
	size, err := strconv.ParseInt(strings.TrimSpace(sizePart), 16, 64)
	if err != nil || size < 0 {
		return fmt.Errorf("%w: bad chunk size %q", ErrCorruptChunkedBody, sizePart)
	}
	if size > int64(c.opts.MaxChunkBytes) {
		return fmt.Errorf("%w: chunk of %d bytes exceeds limit %d",
			ErrCorruptChunkedBody, size, c.opts.MaxChunkBytes)
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(c.br, data); err != nil {
		return fmt.Errorf("%w: short chunk body: %v", ErrCorruptChunkedBody, err)
	}
	var crlf [2]byte
	if _, err := io.ReadFull(c.br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return fmt.Errorf("%w: missing CRLF after chunk", ErrCorruptChunkedBody)
	}

	signed := c.opts.Kind == PayloadStreaming || c.opts.Kind == PayloadStreamingTrailer
	if signed {
		got := extensionValue(ext, "chunk-signature")
		if got == "" {
			return fmt.Errorf("%w: chunk has no signature", ErrCorruptChunkedBody)
		}
		want := Sign(c.opts.SigningKey, c.chunkStringToSign(data))
		if !hmac.Equal([]byte(strings.ToLower(got)), []byte(want)) {
			return fmt.Errorf("%w: chunk signature mismatch", ErrSignatureMismatch)
		}
		c.prevSig = want
	}

	if size == 0 {
		c.done = true
		if err := c.readTrailers(); err != nil {
			return err
		}
		return nil
	}
	c.chunk = data
	c.off = 0
	return nil
}

// readTrailers consumes trailer headers up to the terminating blank line and
// verifies x-amz-trailer-signature when present.
func (c *ChunkedReader) readTrailers() error {
	c.trailers = make(map[string]string)
	var canonical strings.Builder
	var names []string
	seen := make(map[string]string)
	for {
		line, err := c.readLine()
		if err != nil {
			if err == io.EOF && strings.TrimSpace(line) == "" {
				// Tolerate a body that ends right after the zero chunk: no
				// trailers at all.
				return nil
			}
			return err
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("%w: malformed trailer %q", ErrCorruptChunkedBody, line)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		seen[name] = strings.TrimSpace(value)
		if name != "x-amz-trailer-signature" {
			names = append(names, name)
		}
	}
	c.trailers = seen

	sig, ok := seen["x-amz-trailer-signature"]
	if !ok || sig == "" {
		return nil
	}
	sort.Strings(names)
	for _, n := range names {
		canonical.WriteString(n)
		canonical.WriteByte(':')
		canonical.WriteString(seen[n])
		canonical.WriteByte('\n')
	}
	sum := HashPayload([]byte(canonical.String()))
	sts := Algorithm + "-TRAILER\n" +
		c.opts.AmzDate + "\n" +
		c.opts.Scope.String() + "\n" +
		c.prevSig + "\n" +
		sum
	want := Sign(c.opts.SigningKey, sts)
	if !hmac.Equal([]byte(strings.ToLower(sig)), []byte(want)) {
		return fmt.Errorf("%w: trailer signature mismatch", ErrSignatureMismatch)
	}
	return nil
}

// chunkStringToSign builds the per-chunk string to sign.
func (c *ChunkedReader) chunkStringToSign(data []byte) string {
	return Algorithm + "-PAYLOAD\n" +
		c.opts.AmzDate + "\n" +
		c.opts.Scope.String() + "\n" +
		c.prevSig + "\n" +
		EmptyStringSHA256 + "\n" +
		HashPayload(data)
}

// readLine reads one CRLF-terminated line, returning it without the CRLF. A
// trailing LF without CR is accepted for tolerance. io.EOF is returned together
// with whatever was read when the stream ends mid-line.
func (c *ChunkedReader) readLine() (string, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return strings.TrimRight(line, "\r\n"), err
	}
	if len(line) > 8192 {
		return "", fmt.Errorf("%w: chunk header line too long", ErrCorruptChunkedBody)
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// extensionValue extracts a ;name=value extension from a chunk header.
func extensionValue(ext, name string) string {
	for _, part := range strings.Split(ext, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
