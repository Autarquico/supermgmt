package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNestedWriteTx is returned when WithWriteTx is called from inside another
// write transaction. The writer pool has one connection, so nesting would
// deadlock; it is rejected instead.
var ErrNestedWriteTx = errors.New("nested write transaction")

// Querier is what repositories need; both *Tx and the reader pool satisfy it,
// so callers decide the transaction.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tx is a writer transaction opened with BEGIN IMMEDIATE.
type Tx struct{ *sql.Tx }

type writeTxKey struct{}

// WithWriteTx runs fn inside BEGIN IMMEDIATE on the writer. It commits when fn
// returns nil and rolls back on error or panic (the panic is re-raised).
func (d *DB) WithWriteTx(ctx context.Context, fn func(ctx context.Context, tx *Tx) error) (err error) {
	if ctx.Value(writeTxKey{}) != nil {
		return ErrNestedWriteTx
	}
	sqlTx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin write transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
	}()

	if err := fn(context.WithValue(ctx, writeTxKey{}, struct{}{}), &Tx{sqlTx}); err != nil {
		return withRollback(err, sqlTx)
	}
	if err := sqlTx.Commit(); err != nil {
		return withRollback(fmt.Errorf("commit write transaction: %w", err), sqlTx)
	}
	return nil
}

// withRollback rolls tx back and returns err, joined with the rollback failure if any.
func withRollback(err error, tx *sql.Tx) error {
	if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
		return errors.Join(err, fmt.Errorf("rollback: %w", rbErr))
	}
	return err
}

// Reader returns the read-only pool. Never use it to read data a mutation
// depends on; read inside WithWriteTx instead.
func (d *DB) Reader() Querier { return d.reader }
