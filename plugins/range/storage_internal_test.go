// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDBSetup() (*sql.DB, error) {
	db, err := loadDB(":memory:")
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

var expire = int(time.Date(2000, 01, 01, 00, 00, 00, 00, time.UTC).Unix())
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
	db, err := testDBSetup()
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	parsedRec, err := loadRecords(db)
	if err != nil {
		t.Fatalf("Failed to load records from file: %v", err)
	}

	mapRec := make(map[string]*Record)
	for _, rec := range records {
		var (
			ip, mac, hostname string
			expiry            int
		)
		if err := db.QueryRow("select mac, ip, expiry, hostname from leases4 where mac = ?", rec.mac).Scan(&mac, &ip, &expiry, &hostname); err != nil {
			t.Fatalf("record not found for mac=%s: %v", rec.mac, err)
		}
		mapRec[mac] = &Record{IP: net.ParseIP(ip), expires: expiry, hostname: hostname}
	}

	assert.Equal(t, mapRec, parsedRec, "Loaded records differ from what's in the DB")
}

func TestWriteRecords(t *testing.T) {
	pl := PluginState{}
	if err := pl.registerBackingDB(":memory:"); err != nil {
		t.Fatalf("Could not setup file")
	}

	mapRec := make(map[string]*Record)
	for _, rec := range records {
		hwaddr, err := net.ParseMAC(rec.mac)
		if err != nil {
			// bug in testdata
			panic(err)
		}
		if err := pl.saveIPAddress(hwaddr, rec.ip); err != nil {
			t.Errorf("Failed to save ip for %s: %v", hwaddr, err)
		}
		mapRec[hwaddr.String()] = &Record{IP: rec.ip.IP, expires: rec.ip.expires, hostname: rec.ip.hostname}
	}

	parsedRec, err := loadRecords(pl.leasedb)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, mapRec, parsedRec, "Loaded records differ from what's in the DB")
}

func TestFreeIPAddress(t *testing.T) {
	db, err := testDBSetup()
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	pl := PluginState{leasedb: db}

	hwaddr, err := net.ParseMAC(records[1].mac)
	if err != nil {
		t.Fatalf("Failed to parse MAC address: %v", err)
	}

	record := records[1].ip

	parsedRecords, err := loadRecords(pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	_, exists := parsedRecords[hwaddr.String()]
	assert.True(t, exists, "Record should exist before deletion")

	// Now free the IP address
	if err := pl.freeIPAddress(hwaddr, record); err != nil {
		t.Errorf("Failed to free IP address: %v", err)
	}

	parsedRecords, err = loadRecords(pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records after deletion: %v", err)
	}
	_, exists = parsedRecords[hwaddr.String()]
	assert.False(t, exists, "Record should not exist after deletion")
}

func TestFreeIPAddressNonExistent(t *testing.T) {
	pl := PluginState{}
	if err := pl.registerBackingDB(":memory:"); err != nil {
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

	err = pl.freeIPAddress(hwaddr, record)
	assert.NoError(t, err, "Freeing a non-existent IP address should not return an error")

	parsedRecords, err := loadRecords(pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	assert.Empty(t, parsedRecords, "Database should be empty")
}

func TestFreeIPAddressVerifyDeletion(t *testing.T) {
	db, err := testDBSetup()
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	pl := PluginState{leasedb: db}

	parsedRecords, err := loadRecords(pl.leasedb)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	assert.Len(t, parsedRecords, 6, "Should have 6 records from testDBSetup")

	// Delete the middle record (records[2] = "02:00:00:00:00:02" with IP 10.0.0.2)
	hwaddrToDelete, _ := net.ParseMAC(records[2].mac)
	recordToDelete := records[2].ip

	if err := pl.freeIPAddress(hwaddrToDelete, recordToDelete); err != nil {
		t.Errorf("Failed to free IP address: %v", err)
	}

	parsedRecords, err = loadRecords(pl.leasedb)
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

	db, err := testDBSetup()
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

	pl := PluginState{leasedb: db}

	hwaddr, err := net.ParseMAC(records[0].mac)
	if err != nil {
		t.Fatalf("Failed to parse MAC address: %v", err)
	}

	record := records[0].ip

	err = pl.freeIPAddress(hwaddr, record)

	assert.Error(t, err, "Should return error due to trigger preventing deletion")
	assert.Contains(t, err.Error(), "record delete failed", "Error should indicate record delete failure")
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
			db, err := loadDB(":memory:")
			require.NoError(t, err)
			_, err = db.Exec(
				"insert into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)",
				tc.mac, tc.ip, tc.expiry, "host",
			)
			require.NoError(t, err)

			_, err = loadRecords(db)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}
}

func TestLoadRecordsQueryError(t *testing.T) {
	db, err := loadDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = loadRecords(db)
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

	_, err = loadRecords(db)
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

	_, err := loadDB("irrelevant")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

func TestRegisterBackingDBDoubleRegistration(t *testing.T) {
	pl := PluginState{}
	require.NoError(t, pl.registerBackingDB(":memory:"))

	err := pl.registerBackingDB(":memory:")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot swap out a lease database")
}
