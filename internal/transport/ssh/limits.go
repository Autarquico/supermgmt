package ssh

import "bytes"

// limitedBuffer collects command output up to maxBytes and maxLines (0 means
// unlimited lines). Write always reports full consumption: once a limit is hit
// the rest is discarded, so the remote command is never blocked on a full pipe.
type limitedBuffer struct {
	buf       bytes.Buffer
	maxBytes  int
	maxLines  int
	lines     int
	truncated bool
}

func newLimitedBuffer(maxBytes, maxLines int) *limitedBuffer {
	return &limitedBuffer{maxBytes: maxBytes, maxLines: maxLines}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && !b.truncated {
		room := b.maxBytes - b.buf.Len()
		if room <= 0 || (b.maxLines > 0 && b.lines >= b.maxLines) {
			b.truncated = true
			break
		}
		take := min(len(p), room)
		if b.maxLines > 0 {
			if i := bytes.IndexByte(p[:take], '\n'); i >= 0 {
				take = i + 1
				b.lines++
			}
		}
		b.buf.Write(p[:take])
		p = p[take:]
	}
	return n, nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }
