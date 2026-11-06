// Package testdb runs a private PostgreSQL for tests: one server per test
// binary, one fresh database per test. The server starts with the first
// test that asks for a database, so tests and fuzz workers that need none
// do not start (or download) it.
package testdb

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
)

var (
	mu       sync.Mutex
	started  bool
	startErr error
	pg       *embeddedpostgres.EmbeddedPostgres
	dir      string
	port     uint32
	seq      atomic.Int64
)

// Main runs the tests and stops PostgreSQL if a test started it. Call it
// from TestMain.
func Main(m *testing.M) int {
	code := m.Run()
	mu.Lock()
	defer mu.Unlock()
	if pg != nil {
		_ = pg.Stop()
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	return code
}

func start() error {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return startErr
	}
	started = true
	startErr = func() error {
		var err error
		if dir, err = os.MkdirTemp("", "czpg"); err != nil {
			return err
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		port = uint32(l.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a TCP port fits
		_ = l.Close()
		db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port).
			RuntimePath(filepath.Join(dir, "rt")).DataPath(filepath.Join(dir, "data")).Logger(io.Discard))
		if err := db.Start(); err != nil {
			return fmt.Errorf("start postgres: %w", err)
		}
		pg = db
		return nil
	}()
	return startErr
}

// URL creates an empty database for the test and returns its URL.
func URL(t testing.TB) string {
	t.Helper()
	if err := start(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	c, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	name := fmt.Sprintf("t%d_%d", os.Getpid(), seq.Add(1))
	if _, err := c.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/%s?sslmode=disable", port, name)
}
