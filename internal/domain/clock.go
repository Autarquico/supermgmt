package domain

import "time"

// Clock is the only source of time for domain and application code.
type Clock interface{ Now() time.Time }

// SystemClock reads the wall clock in UTC. It is the only caller of time.Now.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// UnixMillis is the persisted representation of an instant.
func UnixMillis(t time.Time) int64 { return t.UnixMilli() }

// FromUnixMillis restores an instant persisted with UnixMillis, in UTC.
func FromUnixMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
