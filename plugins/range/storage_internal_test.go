// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDBSetup(ctx context.Context) (*sql.DB, error) {
	db, err := loadDB(ctx, ":memory:")
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if _, err := db.Exec(
			"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
			record.mac, record.ip.IP.String(), record.ip.expires, record.ip.hostname,
		); err != nil {
			return nil, fmt.Errorf("failed to insert record into test db: %w", err)
		}
	}
	return db, nil
}

var expire = time.Date(2000, 01, 01, 00, 00, 00, 00, time.UTC).Unix()
var records = []struct {
	mac string
	ip  *Record
}{
	{"02:00:00:00:00:00", &Record{IP: net.IPv4(10, 0, 0, 0), expires: expire, hostname: "zero"}},
	{"02:00:00:00:00:01", &Record{IP: net.IPv4(10, 0, 0, 1), expires: expire, hostname: "one"}},
	{"02:00:00:00:00:02", &Record{IP: net.IPv4(10, 0, 0, 2), expires: expire, hostname: "two"}},
	{"02:00:00:00:00:03", &Record{IP: net.IPv4(10, 0, 0, 3), expires: expire, hostname: "three"}},
	{"02:00:00:00:00:04", &Record{IP: net.IPv4(10, 0, 0, 4), expires: expire, hostname: "four"}},
	{"02:00:00:00:00:05", &Record{IP: net.IPv4(10, 0, 0, 5), expires: expire, hostname: "five"}},
}

func TestLoadRecords(t *testing.T) {
	db, err := testDBSetup(t.Context())
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	parsedRec, err := loadRecords(t.Context(), db)
	if err != nil {
		t.Fatalf("Failed to load records from file: %v", err)
	}

	mapRec := make(map[string]*Record)
	for _, rec := range records {
		var (
			ip, mac, hostname string
			expiry            int64
		)
		if err := db.QueryRow("select mac, ip, expiry, hostname from leases4 where mac = ?", rec.mac).Scan(&mac, &ip, &expiry, &hostname); err != nil {
			t.Fatalf("record not found for mac=%s: %v", rec.mac, err)
		}
		mapRec[mac] = &Record{IP: net.ParseIP(ip), expires: expiry, hostname: hostname}
	}

	assert.Equal(t, mapRec, parsedRec, "Loaded records differ from what's in the DB")
}

func TestWriteRecords(t *testing.T) {
	pl := pluginState{}
	if err := pl.registerBackingDB(t.Context(), ":memory:"); err != nil {
		t.Fatalf("Could not setup file")
	}

	mapRec := make(map[string]*Record)
	for _, rec := range records {
		hwaddr, err := net.ParseMAC(rec.mac)
		if err != nil {
			// bug in testdata
			panic(err)
		}
		if err := pl.saveIPAddress(hwaddr.String(), rec.ip); err != nil {
			t.Errorf("Failed to save ip for %s: %v", hwaddr, err)
		}
		mapRec[hwaddr.String()] = &Record{IP: rec.ip.IP, expires: rec.ip.expires, hostname: rec.ip.hostname}
	}

	parsedRec, err := loadRecords(t.Context(), pl.leasedb)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, mapRec, parsedRec, "Loaded records differ from what's in the DB")
}

func TestFreeIPAddress(t *testing.T) {
	db, err := testDBSetup(t.Context())
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	pl := pluginState{leasedb: db}

	hwaddr, err := net.ParseMAC(records[1].mac)
	if err != nil {
		t.Fatalf("Failed to parse MAC address: %v", err)
	}

	record := records[1].ip

	parsedRecords, err := loadRecords(t.Context(), pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	_, exists := parsedRecords[hwaddr.String()]
	assert.True(t, exists, "Record should exist before deletion")

	// Now free the IP address
	if err := pl.freeIPAddress(hwaddr.String(), record); err != nil {
		t.Errorf("Failed to free IP address: %v", err)
	}

	parsedRecords, err = loadRecords(t.Context(), pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records after deletion: %v", err)
	}
	_, exists = parsedRecords[hwaddr.String()]
	assert.False(t, exists, "Record should not exist after deletion")
}

func TestFreeIPAddressNonExistent(t *testing.T) {
	pl := pluginState{}
	if err := pl.registerBackingDB(t.Context(), ":memory:"); err != nil {
		t.Fatalf("Could not setup file")
	}

	hwaddr, err := net.ParseMAC("02:00:00:00:00:99")
	if err != nil {
		t.Fatalf("Failed to parse MAC address: %v", err)
	}

	record := &Record{
		IP:       net.IPv4(10, 0, 0, 99),
		expires:  expire,
		hostname: "non-existent",
	}

	err = pl.freeIPAddress(hwaddr.String(), record)
	assert.NoError(t, err, "Freeing a non-existent IP address should not return an error")

	parsedRecords, err := loadRecords(t.Context(), pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	assert.Empty(t, parsedRecords, "Database should be empty")
}

func TestFreeIPAddressVerifyDeletion(t *testing.T) {
	db, err := testDBSetup(t.Context())
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	pl := pluginState{leasedb: db}

	parsedRecords, err := loadRecords(t.Context(), pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	assert.Len(t, parsedRecords, 6, "Should have 6 records from testDBSetup")

	// Delete the middle record (records[2] = "02:00:00:00:00:02" with IP 10.0.0.2)
	hwaddrToDelete, _ := net.ParseMAC(records[2].mac)
	recordToDelete := records[2].ip

	if err := pl.freeIPAddress(hwaddrToDelete.String(), recordToDelete); err != nil {
		t.Errorf("Failed to free IP address: %v", err)
	}

	parsedRecords, err = loadRecords(t.Context(), pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records after deletion: %v", err)
	}

	assert.Len(t, parsedRecords, 5, "Should have 5 records after deletion")
	_, exists := parsedRecords[hwaddrToDelete.String()]
	assert.False(t, exists, "Deleted record should not exist")

	// Verify some other records still exist
	otherMacs := []string{records[1].mac, records[3].mac}
	for _, mac := range otherMacs {
		_, exists := parsedRecords[mac]
		assert.True(t, exists, "Other records should still exist: %s", mac)
	}
}

func TestFreeIPAddressExecutionError(t *testing.T) {
	// This test triggers a statement execution failure using a SQLite trigger
	// that aborts DELETE operations for records[0]

	db, err := testDBSetup(t.Context())
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}
	defer func() { _ = db.Close() }()

	const triggerErrorMsg = "Custom deletion prevention trigger"
	// Create a trigger that will cause DELETE operations to fail for records[0]
	triggerSQL := fmt.Sprintf(`
		CREATE TRIGGER prevent_delete
		BEFORE DELETE ON leases4
		WHEN OLD.mac = '%s'
		BEGIN
			SELECT RAISE(ABORT, '%s');
		END
	`, records[0].mac, triggerErrorMsg)
	_, err = db.Exec(triggerSQL)
	if err != nil {
		t.Fatalf("Failed to create trigger: %v", err)
	}

	pl := pluginState{leasedb: db}

	hwaddr, err := net.ParseMAC(records[0].mac)
	if err != nil {
		t.Fatalf("Failed to parse MAC address: %v", err)
	}

	record := records[0].ip

	err = pl.freeIPAddress(hwaddr.String(), record)

	assert.Error(t, err, "Should return error due to trigger preventing deletion")
	assert.Contains(t, err.Error(), "could not remove the lease", "Error should indicate record delete failure")
	assert.Contains(t, err.Error(), triggerErrorMsg, "Error should contain trigger message")
}

// TestLoadRecordsMalformedRows covers loadRecords' validation of rows that
// were written directly with raw SQL, bypassing saveIPAddress's guarantees
// (mac/ip are just TEXT columns as far as SQLite is concerned).
func TestLoadRecordsMalformedRows(t *testing.T) {
	cases := []struct {
		name       string
		mac        string
		ip         string
		expiry     any
		wantErrSub string
	}{
		{"malformed MAC", "not-a-mac", "10.0.0.1", 1, "malformed hardware address"},
		{"malformed IP", "aa:bb:cc:dd:ee:ff", "not-an-ip", 1, "expected an IPv4 address"},
		{"IPv6 address instead of IPv4", "aa:bb:cc:dd:ee:ff", "2001:db8::1", 1, "expected an IPv4 address"},
		{"non-numeric expiry", "aa:bb:cc:dd:ee:ff", "10.0.0.1", "not-a-number", "failed to scan row"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := loadDB(t.Context(), ":memory:")
			require.NoError(t, err)
			_, err = db.Exec(
				"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
				tc.mac, tc.ip, tc.expiry, "host",
			)
			require.NoError(t, err)

			_, err = loadRecords(t.Context(), db)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}
}

func TestLoadRecordsQueryError(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = loadRecords(t.Context(), db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to query leases database")
}

// errRowsDriver is a minimal database/sql/driver implementation whose Rows
// always fail iteration with a non-io.EOF error, so that we can
// deterministically exercise loadRecords' rows.Err() branch. Real SQLite
// query results are materialized up front, so this can't be triggered
// through the sqlite driver itself.
type errRowsDriver struct{}

func (errRowsDriver) Open(string) (driver.Conn, error) { return &errRowsConn{}, nil }

type errRowsConn struct{}

func (c *errRowsConn) Prepare(string) (driver.Stmt, error) { return &errRowsStmt{}, nil }
func (c *errRowsConn) Close() error                        { return nil }
func (c *errRowsConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsupported") }

type errRowsStmt struct{}

func (s *errRowsStmt) Close() error  { return nil }
func (s *errRowsStmt) NumInput() int { return -1 }
func (s *errRowsStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("unsupported")
}
func (s *errRowsStmt) Query([]driver.Value) (driver.Rows, error) { return &errRows{}, nil }

type errRows struct{}

func (r *errRows) Columns() []string { return []string{"mac", "ip", "expiry", "hostname"} }
func (r *errRows) Close() error      { return nil }
func (r *errRows) Next([]driver.Value) error {
	return errors.New("simulated row iteration failure")
}

func TestLoadRecordsRowsIterationError(t *testing.T) {
	const driverName = "rangeplugin_errrows_test"
	sql.Register(driverName, errRowsDriver{})

	db, err := sql.Open(driverName, "irrelevant")
	require.NoError(t, err)

	_, err = loadRecords(t.Context(), db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed lease database row scanning")
	assert.Contains(t, err.Error(), "simulated row iteration failure")
}

func TestLoadDBOpenError(t *testing.T) {
	orig := sqlOpen
	t.Cleanup(func() { sqlOpen = orig })
	sqlOpen = func(string, string) (*sql.DB, error) {
		return nil, errors.New("simulated open failure")
	}

	_, err := loadDB(t.Context(), "irrelevant")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

func TestRegisterBackingDBDoubleRegistration(t *testing.T) {
	pl := pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), ":memory:"))

	err := pl.registerBackingDB(t.Context(), ":memory:")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot swap out a lease database")
}

func TestValidateDBPath(t *testing.T) {
	for _, tc := range []struct {
		name, path, wantErrSub string
	}{
		{name: "a relative path", path: "leases.db"},
		{name: "an absolute path", path: "/var/lib/coredhcp/leases.db"},
		{name: "the in-memory store", path: ":memory:"},
		{name: "a path with a space", path: "/var/lib/core dhcp/leases.db"},
		{name: "a query string", path: "leases.db?mode=memory", wantErrSub: `may not contain "?"`},
		{name: "a fragment", path: "leases.db#tail", wantErrSub: `may not contain "#"`},
		{name: "both, the first one wins", path: "leases.db#a?b", wantErrSub: `may not contain "#"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDBPath(tc.path)
			if tc.wantErrSub == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}
}

// TestLoadDBRejectsURIPathBeforeOpen pins where the check happens. The driver
// reads the DSN as a URI, so "leases.db?mode=memory" would open an in-memory
// store and lose every lease at the next restart without a word in the log.
// A rejected path must never reach sql.Open at all.
func TestLoadDBRejectsURIPathBeforeOpen(t *testing.T) {
	orig := sqlOpen
	t.Cleanup(func() { sqlOpen = orig })
	sqlOpen = func(string, string) (*sql.DB, error) {
		t.Error("sql.Open must not be reached for a rejected path")
		return nil, errors.New("unreachable")
	}

	_, err := loadDB(t.Context(), "leases.db?mode=memory")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "may not contain")
}

// holdWriteLock opens its own connection to the database at path, starts a
// write transaction and leaves it open, so any other connection's write
// against the same file fails with SQLITE_BUSY for as long as the calling
// test runs. The transaction is rolled back and the connection closed in
// t.Cleanup.
func holdWriteLock(t *testing.T, path string) {
	t.Helper()
	db, err := loadDB(t.Context(), path)
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(),
		"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
		"ff:ff:ff:ff:ff:ff", "10.255.255.255", 1, "lock-holder")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = tx.Rollback()
		_ = db.Close()
	})
}

// TestIsBusy pins telling a locked database apart from every other kind of
// failure: a plain error and a non-busy sqlite error both read as not busy,
// only SQLITE_BUSY or SQLITE_LOCKED does.
func TestIsBusy(t *testing.T) {
	t.Run("a plain error is never busy", func(t *testing.T) {
		assert.False(t, isBusy(errors.New("boom")))
	})

	t.Run("a non-busy sqlite error is not busy either", func(t *testing.T) {
		// Reuses the constraint-failure shape from
		// TestFreeIPAddressExecutionError: a BEFORE DELETE trigger raising
		// ABORT is a real sqlite error, just not a busy one.
		db, err := loadDB(t.Context(), ":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		_, err = db.Exec(`
			CREATE TRIGGER prevent_delete
			BEFORE DELETE ON leases4
			BEGIN
				SELECT RAISE(ABORT, 'blocked');
			END
		`)
		require.NoError(t, err)
		_, err = db.Exec(
			"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
			"aa:bb:cc:dd:ee:ff", "10.0.0.1", 1, "host",
		)
		require.NoError(t, err)

		_, err = db.Exec("delete from leases4 where mac = ?", "aa:bb:cc:dd:ee:ff")
		require.Error(t, err)
		assert.False(t, isBusy(err))
	})

	t.Run("a locked database is busy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "leases.db")
		holdWriteLock(t, path)

		db2, err := loadDB(t.Context(), path)
		require.NoError(t, err)
		t.Cleanup(func() { _ = db2.Close() })

		_, err = db2.ExecContext(t.Context(),
			"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
			"11:22:33:44:55:66", "10.0.0.2", 1, "host2")
		require.Error(t, err)
		assert.True(t, isBusy(err))
	})
}

// TestStoreErrorBusy pins that storeError wraps a locked-database failure in
// ErrBusy, which is what lets a caller retry that and only that.
func TestStoreErrorBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.db")
	holdWriteLock(t, path)

	db2, err := loadDB(t.Context(), path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db2.Close() })

	_, err = db2.ExecContext(t.Context(),
		"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
		"22:33:44:55:66:77", "10.0.0.3", 1, "host3")
	require.Error(t, err)
	assert.ErrorIs(t, storeError("op", err), ErrBusy)
}

// TestEnqueueQueueFull pins that a lease change is refused rather than
// waited on when the writer is too far behind to keep up: the caller has the
// plugin lock in hand, so blocking on the channel is not an option.
func TestEnqueueQueueFull(t *testing.T) {
	pl := &pluginState{writes: make(chan leaseWrite, 1)}
	// Nothing ever drains this, so one write is enough to fill it; its
	// contents do not matter.
	pl.writes <- leaseWrite{}

	rec := &Record{IP: net.IPv4(10, 0, 0, 90), expires: time.Now().Add(time.Hour).Unix()}
	err := pl.saveIPAddress("aa:bb:cc:dd:ee:90", rec)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWriteQueueFull)
}

// TestApplyWriteNotFound pins the ErrNotFound sentinel applyWrite returns for
// a delete that matched no row. enqueue's inline path treats this as
// success, so this calls applyWrite directly to reach the sentinel itself.
func TestApplyWriteNotFound(t *testing.T) {
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), ":memory:"))

	err := pl.applyWrite(leaseWrite{
		op:    "remove",
		mac:   "aa:bb:cc:dd:ee:ff",
		ip:    "10.0.0.1",
		query: `delete from leases4 where mac = ? and ip = ?`,
		args:  []any{"aa:bb:cc:dd:ee:ff", "10.0.0.1"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestWriterAppliesQueuedWritesInOrder pins the invariant startWriter exists
// for: queued changes are applied in the order they were made. Queuing the
// delete after the insert and finding the row gone once the writer has
// drained is what proves the order held; applied the other way around, the
// row would still be there.
func TestWriterAppliesQueuedWritesInOrder(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), dbPath))
	pl.dbCtx, pl.dbCancel = context.WithCancel(t.Context())
	pl.startWriter()

	rec := &Record{IP: net.IPv4(10, 0, 0, 91), expires: time.Now().Add(time.Hour).Unix(), hostname: "h"}
	require.NoError(t, pl.saveIPAddress("aa:bb:cc:dd:ee:91", rec))
	require.NoError(t, pl.freeIPAddress("aa:bb:cc:dd:ee:91", rec))
	pl.stopWriter()

	recs, err := loadRecords(t.Context(), pl.leasedb)
	require.NoError(t, err)
	assert.Empty(t, recs, "the delete queued after the insert must win")
}

// TestDrainWritesAppliesEverythingQueued pins that shutting the writer down
// does not throw away whatever is still queued: every row handed to it must
// be on disk once it returns. Calling drainWrites directly, rather than
// racing it against the writer goroutine, is what makes the queued items
// still be there deterministically.
func TestDrainWritesAppliesEverythingQueued(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), dbPath))
	pl.writes = make(chan leaseWrite, 8)

	macs := []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}
	for i, mac := range macs {
		rec := &Record{IP: net.IPv4(10, 0, 0, byte(92+i)), expires: time.Now().Add(time.Hour).Unix(), hostname: "h"}
		pl.writes <- leaseWrite{
			op:    "store",
			mac:   mac,
			ip:    rec.IP.String(),
			query: `insert or replace into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)`,
			args:  []any{mac, rec.IP.String(), rec.expires, rec.hostname},
		}
	}

	pl.drainWrites()

	recs, err := loadRecords(t.Context(), pl.leasedb)
	require.NoError(t, err)
	assert.Len(t, recs, len(macs), "every queued write must be on disk")
}

// TestWriteSwallowsNotFound pins that a queued delete for a row that is
// already gone does not upset the writer: it is logged at debug level and
// the writer shuts down cleanly, same as for any other change.
func TestWriteSwallowsNotFound(t *testing.T) {
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), ":memory:"))
	pl.startWriter()

	require.NoError(t, pl.freeIPAddress("aa:bb:cc:dd:ee:ff", &Record{IP: net.IPv4(10, 0, 0, 1)}))
	pl.stopWriter()

	recs, err := loadRecords(t.Context(), pl.leasedb)
	require.NoError(t, err)
	assert.Empty(t, recs, "nothing was there to begin with, and nothing must appear")
}

// TestWriteFailureIsLoggedNotFatal pins that a write the database itself
// cannot take is logged rather than treated as fatal: nothing is waiting on
// the result, so the writer's only job is to say so and move on.
func TestWriteFailureIsLoggedNotFatal(t *testing.T) {
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), ":memory:"))
	pl.startWriter()

	// A closed database fails every statement with "sql: database is
	// closed", which is not a busy error, so this does not retry either.
	require.NoError(t, pl.leasedb.Close())

	rec := &Record{IP: net.IPv4(10, 0, 0, 93), expires: time.Now().Add(time.Hour).Unix(), hostname: "h"}
	require.NoError(t, pl.saveIPAddress("aa:bb:cc:dd:ee:93", rec))
	pl.stopWriter()
}

// TestWriteBusyRetry pins that write's busy-retry loop gives up after
// busyRetries attempts instead of blocking the writer forever: with the
// write lock held by another transaction for the whole test, the queued
// write exhausts its retries and stopWriter still returns quickly.
// busyRetries is 3 and busyBackoff 20ms, so this comfortably finishes well
// under a second.
func TestWriteBusyRetry(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), dbPath))
	holdWriteLock(t, dbPath)
	pl.startWriter()

	rec := &Record{IP: net.IPv4(10, 0, 0, 94), expires: time.Now().Add(time.Hour).Unix(), hostname: "h"}
	require.NoError(t, pl.saveIPAddress("aa:bb:cc:dd:ee:94", rec))

	start := time.Now()
	pl.stopWriter()
	assert.Less(t, time.Since(start), 500*time.Millisecond, "the retries must not hang past their backoff budget")
}

// TestSaveIPAddressSurvives2038 is the regression test for a 32-bit build
// storing the lease expiry as a 32-bit value: a lease expiring after the
// 2038 Unix-time rollover must round-trip through storage exactly and must
// not read as already expired.
func TestSaveIPAddressSurvives2038(t *testing.T) {
	pl := &pluginState{}
	require.NoError(t, pl.registerBackingDB(t.Context(), ":memory:"))

	expires := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	rec := &Record{IP: net.IPv4(10, 0, 0, 99), expires: expires, hostname: "future"}
	require.NoError(t, pl.saveIPAddress("aa:bb:cc:dd:ee:99", rec))

	recs, err := loadRecords(t.Context(), pl.leasedb)
	require.NoError(t, err)
	got, ok := recs["aa:bb:cc:dd:ee:99"]
	require.True(t, ok)
	assert.Equal(t, expires, got.expires, "the expiry must round-trip exactly")

	at2099 := time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
	assert.False(t, got.expired(at2099), "a lease this far out must not read as already expired")
}
