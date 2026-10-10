// Package database owns SQLite access (spec §9, ADR-0001).
//
// Two pools are built from two different DSNs: a writer with exactly one
// connection (BEGIN IMMEDIATE, WAL, synchronous=FULL) and a reader with four
// query_only connections. All pragmas travel in the DSN so every connection
// the pool ever opens, including replacements, carries them.
//
// Mutation paths must never read through the reader pool: everything a
// mutation decides on is read inside the writer transaction (WithWriteTx), so
// the decision and the write see one consistent snapshot. The reader pool is
// for queries that do not feed a mutation.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	defaultBusyTimeout = 5 * time.Second
	readerConnections  = 4
)

// Options tunes Open. The zero value is valid.
type Options struct {
	// BusyTimeout is how long a connection waits for a lock (storage.sqlite.busy_timeout).
	BusyTimeout time.Duration
	// Clock stamps migrations. Defaults to domain.SystemClock.
	Clock domain.Clock
}

// DB is the writer/reader pool pair.
type DB struct {
	writer *sql.DB
	reader *sql.DB
	clock  domain.Clock
}

// Open opens (creating if needed) the database at path. The writer is opened
// first so the file exists and is in WAL mode before the reader attaches.
func Open(ctx context.Context, path string, opts Options) (*DB, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = defaultBusyTimeout
	}
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	busy := opts.BusyTimeout.Milliseconds()

	writer, err := openPool(ctx, path, writerQuery(busy), 1)
	if err != nil {
		return nil, fmt.Errorf("open writer: %w", err)
	}
	reader, err := openPool(ctx, path, readerQuery(busy), readerConnections)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("open reader: %w", err)
	}
	return &DB{writer: writer, reader: reader, clock: opts.Clock}, nil
}

// Close closes both pools.
func (d *DB) Close() error {
	return errors.Join(d.writer.Close(), d.reader.Close())
}

func writerQuery(busyMillis int64) url.Values {
	return pragmaQuery(url.Values{"_txlock": {"immediate"}},
		"journal_mode(WAL)",
		"foreign_keys(1)",
		fmt.Sprintf("busy_timeout(%d)", busyMillis),
		"synchronous(FULL)",
	)
}

func readerQuery(busyMillis int64) url.Values {
	return pragmaQuery(url.Values{},
		"foreign_keys(1)",
		fmt.Sprintf("busy_timeout(%d)", busyMillis),
		"query_only(1)",
	)
}

func pragmaQuery(q url.Values, pragmas ...string) url.Values {
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	return q
}

func openPool(ctx context.Context, path string, query url.Values, maxConns int) (*sql.DB, error) {
	pool, err := sql.Open("sqlite", dsn(path, query))
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(maxConns)
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		return nil, err
	}
	return pool, nil
}

func dsn(path string, query url.Values) string {
	u := url.URL{Path: path}
	return "file:" + u.EscapedPath() + "?" + query.Encode()
}
