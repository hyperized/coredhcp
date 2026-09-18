// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
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
	// ErrNotFound reports a write that matched no row. The binding the
	// caller wanted gone is already gone, which is not a failure, but it is
	// worth telling apart from a write that actually did something.
	ErrNotFound = errors.New("range6: no such binding in storage")

	// ErrBusy reports sqlite refusing the operation because another writer
	// holds the database. It is transient: the writer retries a few times
	// before giving up on the change.
	ErrBusy = errors.New("range6: lease database is busy")

	// ErrCorruptRecord reports a stored row that does not make sense. The
	// lease file is a plain sqlite database an operator can edit, so a row
	// that cannot be parsed stops the server at startup rather than putting
	// a bogus address into the allocator.
	ErrCorruptRecord = errors.New("range6: corrupt binding record")

	// ErrWriteQueueFull reports a change that could not be queued because
	// the writer is that far behind. The caller abandons the change rather
	// than waiting for the disk with the plugin lock in hand.
	ErrWriteQueueFull = errors.New("range6: binding write queue is full")

	// ErrWriterStopped reports a change queued after the writer had been
	// shut down, which nothing will apply. Only a stopped plugin does that,
	// so in the server it never happens: it is here so a caller waiting for
	// a write gets an answer instead of waiting forever.
	ErrWriterStopped = errors.New("range6: binding writer has stopped")
)

// sqlOpen is sql.Open, extracted as a seam for tests. The registered
// "sqlite" driver only implements driver.Driver (not driver.DriverContext),
// so database/sql defers connecting until first use and sql.Open itself
// never actually fails for it; overriding this var is the only way to
// exercise the error path below deterministically.
var sqlOpen = sql.Open

const (
	// writeQueueLen is how many binding changes may be waiting for the
	// disk. It bounds how far storage may lag memory, and therefore how
	// much a crash loses.
	writeQueueLen = 1024

	// writeTimeout bounds how long a client waits for its binding to reach
	// the disk. The context is made when the change is queued, so it covers
	// the wait in the queue and every attempt at the statement together. A
	// write to a local sqlite file takes microseconds; one that takes
	// seconds is one the client has already retransmitted past, so the
	// binding is refused rather than waited on any longer.
	writeTimeout = 2 * time.Second

	// loadTimeout bounds the startup read of the binding table. Long enough
	// for a large table on slow storage, short enough that a server which
	// cannot read its bindings says so instead of hanging in setup.
	loadTimeout = 30 * time.Second

	// busyRetries is how many extra attempts a write gets when sqlite says
	// the database is locked, and busyBackoff how long the writer waits
	// between them. A lock another process held for a moment should not
	// cost a client its binding, and the retries cost nothing extra in the
	// worst case: they run inside the same writeTimeout the caller is
	// already waiting out.
	busyRetries = 3
	busyBackoff = 20 * time.Millisecond
)

// dsnReservedChars are the characters that stop a path being just a path once
// it is pasted into the "file:" URI the sqlite driver parses. '?' opens the
// query string, so a configured "leases6.db?mode=memory" quietly gives you an
// in-memory store and every binding is gone at the next restart; '#' opens a
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

// loadDB opens the lease database and makes sure the table is there.
//
// The DUID is stored as a blob because it is opaque octets, not text: RFC 8415
// §11 lets a client pick any of four DUID forms and two of them are binary. It
// pairs with the IAID as the primary key, which is exactly what identifies one
// address association.
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
	if _, err := db.ExecContext(ctx, "create table if not exists leases6 (duid blob, iaid int, ip text, expiry int, hostname text, primary key (duid, iaid))"); err != nil {
		return nil, storeError("table creation failed", err)
	}
	return db, nil
}

// iaidValue turns an IAID into the integer stored in the iaid column. An IAID
// is four opaque octets, read big-endian so the stored value orders the same
// way the bytes do.
func iaidValue(iaid [4]byte) int64 {
	return int64(binary.BigEndian.Uint32(iaid[:]))
}

// recordFromRow validates one stored row and turns it into a Record.
//
// Every field is checked even though this process wrote them: the file is a
// plain sqlite database an operator can edit, and a row that does not make
// sense must stop the server at startup rather than put a bogus address into
// the allocator.
func recordFromRow(duid []byte, iaid int64, ip string, expiry int64, hostname string) (*Record, error) {
	if len(duid) == 0 || len(duid) > maxDUIDLen {
		return nil, fmt.Errorf("%w: stored client DUID is %d octets, want 1 to %d", ErrCorruptRecord, len(duid), maxDUIDLen)
	}
	if iaid < 0 || iaid > math.MaxUint32 {
		return nil, fmt.Errorf("%w: stored IAID %d is outside the 32-bit range", ErrCorruptRecord, iaid)
	}
	addr := net.ParseIP(ip)
	if addr.To16() == nil || addr.To4() != nil {
		return nil, fmt.Errorf("%w: expected an IPv6 address, got: %v", ErrCorruptRecord, ip)
	}
	rec := &Record{DUID: duid, IP: addr.To16(), expires: expiry, hostname: hostname}
	// The conversion is safe: iaid was bounds-checked against MaxUint32
	// just above.
	binary.BigEndian.PutUint32(rec.IAID[:], uint32(iaid))
	return rec, nil
}

// loadRecords reads every stored binding, keyed the way the in-memory map is.
func loadRecords(ctx context.Context, db *sql.DB) (map[string]*Record, error) {
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	rows, err := db.QueryContext(ctx, "select duid, iaid, ip, expiry, hostname from leases6")
	if err != nil {
		return nil, storeError("failed to query leases database", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		duid         []byte
		iaid         int64
		ip, hostname string
		expiry       int64
		records      = make(map[string]*Record)
	)
	for rows.Next() {
		if err := rows.Scan(&duid, &iaid, &ip, &expiry, &hostname); err != nil {
			return nil, storeError("failed to scan row", err)
		}
		rec, err := recordFromRow(duid, iaid, ip, expiry, hostname)
		if err != nil {
			return nil, err
		}
		records[rec.key()] = rec
	}
	if err := rows.Err(); err != nil {
		return nil, storeError("failed lease database row scanning", err)
	}
	return records, nil
}

// bindingWrite is one queued change to the lease database: the statement, its
// arguments, and enough of the binding to name it in a log line. The
// description is put together only when a write fails, which is why the DUID
// and the address travel alongside the arguments instead of as one string.
type bindingWrite struct {
	op    string
	duid  []byte
	iaid  [4]byte
	ip    string
	query string
	args  []any

	// ctx bounds the whole change, from the moment it was queued, and
	// cancel releases it once the writer is done with it. done carries the
	// result back to the handler waiting on it, and is buffered so the
	// writer never blocks on a caller that has already given up.
	//nolint:containedctx // travels with the queued change to the writer
	ctx    context.Context
	cancel context.CancelFunc
	done   chan error
}

// pendingWrite is a queued change from the point of view of whoever made it:
// the result to wait for, and how to put the in-memory change back when that
// result is a failure.
//
// undo is nil for a change that cannot be undone. Removing a binding is the
// case: the address went back to the pool under the same lock, another
// client may hold it by the time the delete fails, and handing the record
// back would then put two clients on one address. The row stays on disk
// instead, which a restart reads as a binding for its original owner and the
// sweeper clears once it expires.
type pendingWrite struct {
	done chan error
	undo func()
}

// describe names the change for a log line.
func (w bindingWrite) describe() string {
	return fmt.Sprintf("%s the binding for DUID %x IAID %x on %s", w.op, w.duid, w.iaid, w.ip)
}

// saveIPAddress writes out a binding to storage.
// undo is run under the plugin lock if the write fails, to put the
// in-memory change back.
func (p *pluginState) saveIPAddress(record *Record, undo func()) error {
	ip := record.IP.String()
	return p.enqueue(bindingWrite{
		op:    "store",
		duid:  record.DUID,
		iaid:  record.IAID,
		ip:    ip,
		query: `insert or replace into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)`,
		args:  []any{record.DUID, iaidValue(record.IAID), ip, record.expires, record.hostname},
	}, undo)
}

// freeIPAddress removes a binding from storage. The address is part of the
// condition so a row that has meanwhile been replaced by one for a different
// address is left alone.
func (p *pluginState) freeIPAddress(record *Record) error {
	ip := record.IP.String()
	return p.enqueue(bindingWrite{
		op:    "remove",
		duid:  record.DUID,
		iaid:  record.IAID,
		ip:    ip,
		query: `delete from leases6 where duid = ? and iaid = ? and ip = ?`,
		args:  []any{record.DUID, iaidValue(record.IAID), ip},
	}, nil)
}

// enqueue hands one change to the writer goroutine.
//
// The plugin lock is held here, so this must not block: the whole point of
// the writer is that the disk is no longer on the far side of that lock. A
// queue that has filled up is reported instead of waited on, and the caller
// abandons the change it was about to make, which is what keeps memory and
// storage from drifting apart under a backlog.
//
// A state with no writer running applies the write inline and reports the
// result at once, so there is nothing pending to wait for. That is the zero
// value a test builds by hand, never a plugin that setup produced. It draws
// the same conclusion from a change that matched nothing as the writer does:
// the row is already in the state the caller wanted, so there is nothing to
// report.
func (p *pluginState) enqueue(w bindingWrite, undo func()) error {
	w.ctx, w.cancel = context.WithTimeout(p.storeContext(), writeTimeout)
	w.done = make(chan error, 1)

	if p.writes == nil {
		defer w.cancel()
		if err := p.applyWrite(w); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		return nil
	}
	select {
	case p.writes <- w:
		p.pending = append(p.pending, pendingWrite{done: w.done, undo: undo})
		return nil
	default:
		w.cancel()
		return fmt.Errorf("could not %s: %w", w.describe(), ErrWriteQueueFull)
	}
}

// takePending hands the caller the changes queued since the lock was taken
// and clears the list.
//
// One caller at a time: every enqueue happens with the plugin lock held, so
// the only changes on the list are the ones this caller just made. The
// caller has to take them before it releases the lock, which is what
// withLock does for every path that has one.
func (p *pluginState) takePending() []pendingWrite {
	if len(p.pending) == 0 {
		return nil
	}
	pending := p.pending
	p.pending = nil
	return pending
}

// settleAll waits for every queued change and returns one result each, in
// the order they were queued. A change that failed has its in-memory effect
// undone, under the lock, before this returns.
//
// The invariant this exists for: nothing a client is told outlives the write
// behind it. The handler makes its change in memory under the lock, queues
// the write, drops the lock, and only answers once the row is on disk. A
// crash between the two would otherwise leave a client holding an address
// the next start reads as free, and hands to somebody else.
//
// The caller must not hold the lock: waiting is the whole point, and an undo
// takes the lock again.
func (p *pluginState) settleAll(pending []pendingWrite) []error {
	if len(pending) == 0 {
		return nil
	}
	results := make([]error, len(pending))
	var failed []func()
	for i, pw := range pending {
		results[i] = waitFor(pw.done, p.writerDone)
		if results[i] != nil && pw.undo != nil {
			failed = append(failed, pw.undo)
		}
	}
	if failed == nil {
		return results
	}
	p.Lock()
	defer p.Unlock()
	// Backwards: the last change made is the first one put back.
	for _, f := range slices.Backward(failed) {
		f()
	}
	return results
}

// settle is settleAll for a caller with a single answer to give, reporting
// the first failure among the changes it made.
func (p *pluginState) settle(pending []pendingWrite) error {
	return firstError(p.settleAll(pending))
}

// firstError reports the first failure in a run of results, or nil when they
// all succeeded.
func firstError(results []error) error {
	for _, err := range results {
		if err != nil {
			return err
		}
	}
	return nil
}

// waitFor blocks for one change's result. A writer that exits without
// applying it, which only a stopped plugin does, comes back as a failure
// rather than as a caller that never returns. The result is preferred over
// the writer having gone, because the drain fills every result it has
// before it closes writerDone.
func waitFor(done <-chan error, writerDone <-chan struct{}) error {
	select {
	case err := <-done:
		return err
	default:
	}
	select {
	case err := <-done:
		return err
	case <-writerDone:
		return ErrWriterStopped
	}
}

// applyWrite runs one statement against the database, under the context the
// change was queued with. A delete that matched nothing comes back as
// ErrNotFound: the row is already gone, which is not a failure, but the
// caller tells the two apart.
func (p *pluginState) applyWrite(w bindingWrite) error {
	res, err := p.leasedb.ExecContext(w.ctx, w.query, w.args...)
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
// sequence the map went through, and the delete of an address can never land
// after the insert that hands the same address to the next client.
//
// The handler then waits for its own change here, with the lock released, so
// the reply still stands on a write that finished. What the writer buys is
// not a shorter wait for that one client, it is that every other client, the
// sweeper and the lease API are no longer queued behind the disk.
//
// It must run before the plugin is handed anything to serve: it is what
// installs the queue, and until then writes go to the disk inline.
func (p *pluginState) startWriter() {
	p.writes = make(chan bindingWrite, writeQueueLen)
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
// so a shutdown does not throw away bindings that were already handed out.
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

// write applies one queued change and reports the result to whoever is
// waiting for it, retrying while sqlite says the database is locked and the
// change still has time left on it.
//
// A change that matched no row is reported as a success: the row is already
// in the state the caller wanted. Everything else is the caller's to log and
// to undo, which is why nothing is logged here.
func (p *pluginState) write(w bindingWrite) {
	defer w.cancel()

	var err error
	for attempt := 0; ; attempt++ {
		err = p.applyWrite(w)
		if !errors.Is(err, ErrBusy) || attempt == busyRetries || w.ctx.Err() != nil {
			break
		}
		time.Sleep(busyBackoff)
	}
	if errors.Is(err, ErrNotFound) {
		log.Debugf("%v", err)
		err = nil
	}
	w.done <- err
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

// registerBackingDB installs a database connection string as the backing store
// for bindings.
func (p *pluginState) registerBackingDB(ctx context.Context, filename string) error {
	if p.leasedb != nil {
		return errors.New("cannot swap out a lease database while running")
	}
	// We never close this, but that's ok because plugins are never
	// stopped/unregistered.
	newLeaseDB, err := loadDB(ctx, filename)
	if err != nil {
		return fmt.Errorf("failed to open lease database %s: %w", filename, err)
	}
	p.leasedb = newLeaseDB
	return nil
}
