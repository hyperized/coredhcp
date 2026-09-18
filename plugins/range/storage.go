// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	// The sqlite driver registers itself with database/sql on import, and
	// the pure-Go implementation keeps the build cgo-free. sqlite3 holds the
	// result codes, which is how a locked database is told apart from a
	// broken one.
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Callers can tell these apart with errors.Is. Every error this file returns
// wraps one of them or comes straight from database/sql.
var (
	// ErrNotFound reports a write that matched no row. The lease the caller
	// wanted gone is already gone, which is not a failure, but it is worth
	// telling apart from a write that actually did something.
	ErrNotFound = errors.New("range: no such lease in storage")

	// ErrBusy reports sqlite refusing the operation because another writer
	// holds the database. It is transient: the writer retries a few times
	// before giving up on the change.
	ErrBusy = errors.New("range: lease database is busy")

	// ErrCorruptRecord reports a stored row that does not make sense. The
	// lease file is a plain sqlite database an operator can edit, so a row
	// that cannot be parsed stops the server at startup rather than putting
	// a bogus address into the allocator.
	ErrCorruptRecord = errors.New("range: corrupt lease record")

	// ErrWriteQueueFull reports a lease change that could not be queued
	// because the writer is that far behind. The caller abandons the change
	// rather than waiting for the disk with the plugin lock in hand.
	ErrWriteQueueFull = errors.New("range: lease write queue is full")
)

// sqlOpen is sql.Open, extracted as a seam for tests. The registered
// "sqlite" driver only implements driver.Driver (not driver.DriverContext),
// so database/sql defers connecting until first use and sql.Open itself
// never actually fails for it; overriding this var is the only way to
// exercise the error path below deterministically.
var sqlOpen = sql.Open

const (
	// writeQueueLen is how many lease changes may be waiting for the disk.
	// It bounds how far storage may lag memory, and therefore how much a
	// crash loses. A thousand rows is more than a boot storm on a /24
	// produces and costs a few tens of kilobytes.
	writeQueueLen = 1024

	// writeTimeout bounds one statement. A wedged database has to surface as
	// a logged failure and a growing queue, not as a writer that never
	// returns.
	writeTimeout = 5 * time.Second

	// loadTimeout bounds the startup read of the lease table. Long enough
	// for a large table on slow storage, short enough that a server which
	// cannot read its leases says so instead of hanging in setup.
	loadTimeout = 30 * time.Second

	// busyRetries is how many extra attempts a write gets when sqlite says
	// the database is locked, and busyBackoff how long the writer waits
	// between them. Only the writer goroutine retries: nothing is waiting on
	// it, and losing a lease row to a lock another process held for a
	// moment would be worse than the delay.
	busyRetries = 3
	busyBackoff = 20 * time.Millisecond

	// writeErrorEvery paces the writer's failure log. A database that has
	// gone away fails every write, and one line per packet helps nobody.
	writeErrorEvery = time.Minute
)

// dsnReservedChars are the characters that stop a path being just a path once
// it is pasted into the "file:" URI the sqlite driver parses. '?' opens the
// query string, so a configured "leases.db?mode=memory" quietly gives you an
// in-memory store and every lease is gone at the next restart; '#' opens a
// fragment and truncates the name. Neither belongs in a lease file path, so
// they are refused by name rather than escaped.
const dsnReservedChars = "?#"

// validateDBPath rejects a configured lease database path that would smuggle
// URI syntax into the DSN. It runs before sql.Open so a bad path fails at
// startup instead of producing a store that looks like it works.
func validateDBPath(path string) error {
	i := strings.IndexAny(path, dsnReservedChars)
	if i < 0 {
		return nil
	}
	return fmt.Errorf("lease database path %q may not contain %q", path, path[i:i+1])
}

// isBusy reports whether err is sqlite saying the database is locked. The
// primary result code is the low byte; the extended codes above it say which
// kind of lock it was, which nothing here acts on.
func isBusy(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	switch serr.Code() & 0xff {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return true
	}
	return false
}

// storeError names the operation that failed and marks a locked database as
// such, so a caller can retry that and only that.
func storeError(op string, err error) error {
	if isBusy(err) {
		return fmt.Errorf("%s: %w: %w", op, ErrBusy, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func loadDB(ctx context.Context, path string) (*sql.DB, error) {
	if err := validateDBPath(path); err != nil {
		return nil, err
	}
	db, err := sqlOpen("sqlite", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%T): %w", err, err)
	}
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	if _, err := db.ExecContext(ctx, "create table if not exists leases4 (mac string not null, ip string not null, expiry int, hostname string not null, primary key (mac, ip))"); err != nil {
		return nil, storeError("table creation failed", err)
	}
	return db, nil
}

// loadRecords loads the DHCPv6/v4 Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IP address.
func loadRecords(ctx context.Context, db *sql.DB) (map[string]*Record, error) {
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	rows, err := db.QueryContext(ctx, "select mac, ip, expiry, hostname from leases4")
	if err != nil {
		return nil, storeError("failed to query leases database", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		mac, ip, hostname string
		expiry            int64
		records           = make(map[string]*Record)
	)
	for rows.Next() {
		if err := rows.Scan(&mac, &ip, &expiry, &hostname); err != nil {
			return nil, storeError("failed to scan row", err)
		}
		hwaddr, err := net.ParseMAC(mac)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed hardware address: %s", ErrCorruptRecord, mac)
		}
		ipaddr := net.ParseIP(ip)
		if ipaddr.To4() == nil {
			return nil, fmt.Errorf("%w: expected an IPv4 address, got: %v", ErrCorruptRecord, ipaddr)
		}
		records[hwaddr.String()] = &Record{IP: ipaddr, expires: expiry, hostname: hostname}
	}
	if err := rows.Err(); err != nil {
		return nil, storeError("failed lease database row scanning", err)
	}
	return records, nil
}

// leaseWrite is one queued change to the lease database: the statement, its
// arguments, and enough of the lease to name it in a log line. The
// description is put together only when a write fails, which is why the MAC
// and the address travel alongside the arguments instead of as one string.
type leaseWrite struct {
	op    string
	mac   string
	ip    string
	query string
	args  []any
}

// describe names the change for a log line.
func (w leaseWrite) describe() string {
	return w.op + " the lease for MAC " + w.mac + " on " + w.ip
}

// saveIPAddress writes out a lease to storage. mac is the canonical
// net.HardwareAddr.String() form, which is also the Recordsv4 key: the sweeper
// walks that map and would otherwise have to parse every key back into a
// net.HardwareAddr only to format it again.
func (p *pluginState) saveIPAddress(mac string, record *Record) error {
	ip := record.IP.String()
	return p.enqueue(leaseWrite{
		op:    "store",
		mac:   mac,
		ip:    ip,
		query: `insert or replace into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)`,
		args:  []any{mac, ip, record.expires, record.hostname},
	})
}

// freeIPAddress removes a lease from storage. mac is the canonical
// net.HardwareAddr.String() form, as for saveIPAddress.
func (p *pluginState) freeIPAddress(mac string, record *Record) error {
	ip := record.IP.String()
	return p.enqueue(leaseWrite{
		op:    "remove",
		mac:   mac,
		ip:    ip,
		query: `delete from leases4 where mac = ? and ip = ?`,
		args:  []any{mac, ip},
	})
}

// enqueue hands one change to the writer goroutine.
//
// The plugin lock is held here, so this must not block: the whole point of
// the writer is that the disk is no longer on the far side of that lock. A
// queue that has filled up is reported instead of waited on, and the caller
// abandons the change it was about to make, which is what keeps memory and
// storage from drifting apart under a backlog.
//
// A state with no writer running applies the write inline. That is the zero
// value a test builds by hand, never a plugin that setup produced. It draws
// the same conclusion from a change that matched nothing as the writer does:
// the row is already in the state the caller wanted, so there is nothing to
// report.
func (p *pluginState) enqueue(w leaseWrite) error {
	if p.writes == nil {
		if err := p.applyWrite(w); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		return nil
	}
	select {
	case p.writes <- w:
		return nil
	default:
		return fmt.Errorf("could not %s: %w", w.describe(), ErrWriteQueueFull)
	}
}

// applyWrite runs one statement against the database. A delete that matched
// nothing comes back as ErrNotFound: the row is already gone, which is not a
// failure, but the writer logs the two differently.
func (p *pluginState) applyWrite(w leaseWrite) error {
	ctx, cancel := context.WithTimeout(p.storeContext(), writeTimeout)
	defer cancel()

	res, err := p.leasedb.ExecContext(ctx, w.query, w.args...)
	if err != nil {
		return storeError("could not "+w.describe(), err)
	}
	// The sqlite driver counts the rows as it goes and never fails to report
	// the number, so dropping that error keeps a branch out of here that
	// nothing could reach or test.
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("could not %s: %w", w.describe(), ErrNotFound)
	}
	return nil
}

// storeContext returns the context storage calls run under. It is the
// plugin's own and not a request's: the writer outlives the packet that
// queued a change, and a handler may not hold on to the context it was
// called with. A zero-valued pluginState, which the tests build, has none.
func (p *pluginState) storeContext() context.Context {
	if p.dbCtx == nil {
		return context.Background()
	}
	return p.dbCtx
}

// startWriter runs the goroutine that owns every write to the lease
// database.
//
// The invariant it exists for: a change is queued while the plugin lock is
// held, at the moment the in-memory state changes, and the queue is applied
// in that same order by this one goroutine. Storage therefore replays the
// sequence the map went through and converges on it, and the delete of an
// address can never land after the insert that hands the same address to the
// next client. What it costs is that storage lags memory by at most the
// queue: a crash loses the tail, the same way an unsynced write does.
//
// It must run before the plugin is handed anything to serve: it is what
// installs the queue, and until then writes go to the disk inline.
func (p *pluginState) startWriter() {
	p.writes = make(chan leaseWrite, writeQueueLen)
	p.stopWrites = make(chan struct{})
	p.writerDone = make(chan struct{})
	go func() {
		defer close(p.writerDone)
		for {
			select {
			case <-p.stopWrites:
				p.drainWrites()
				return
			case w := <-p.writes:
				p.write(w)
			}
		}
	}()
}

// drainWrites applies what is still queued when the writer is asked to stop,
// so a shutdown does not throw away leases that were already handed out.
func (p *pluginState) drainWrites() {
	for {
		select {
		case w := <-p.writes:
			p.write(w)
		default:
			return
		}
	}
}

// write applies one queued change, retrying while sqlite says the database is
// locked. Nothing is waiting on the result, so the only thing left to do with
// a failure is log it, paced so a database that has gone away does not bury
// everything else.
func (p *pluginState) write(w leaseWrite) {
	var err error
	for attempt := 0; ; attempt++ {
		if err = p.applyWrite(w); !errors.Is(err, ErrBusy) || attempt == busyRetries {
			break
		}
		time.Sleep(busyBackoff)
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrNotFound):
		// Nothing to undo: whatever the change wanted is already true.
		log.Debugf("%v", err)
	default:
		if skipped, ok := p.writeErrors.ready(p.timeNow(), writeErrorEvery); ok {
			log.Errorf("%v (%d further write failure(s) not logged)", err, skipped)
		}
	}
}

// stopWriter shuts the writer down and waits for it to drain, then ends the
// storage context so nothing reaches the database afterwards.
//
// Nothing in the server calls this: plugins are never stopped, so the writer
// lives as long as the process. It exists so a test does not leave a
// goroutine behind, and so the queue is on disk before the test asserts on
// it. A change queued after this point is dropped rather than written, which
// is why it belongs after the traffic has stopped.
func (p *pluginState) stopWriter() {
	close(p.stopWrites)
	<-p.writerDone
	if p.dbCancel != nil {
		p.dbCancel()
	}
}

// registerBackingDB installs a database connection string as the backing store for leases
func (p *pluginState) registerBackingDB(ctx context.Context, filename string) error {
	if p.leasedb != nil {
		return errors.New("cannot swap out a lease database while running")
	}
	// We never close this, but that's ok because plugins are never stopped/unregistered
	newLeaseDB, err := loadDB(ctx, filename)
	if err != nil {
		return fmt.Errorf("failed to open lease database %s: %w", filename, err)
	}
	p.leasedb = newLeaseDB
	return nil
}
