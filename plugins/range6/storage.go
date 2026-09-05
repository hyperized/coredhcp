// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"

	// The pure-Go sqlite driver registers itself with database/sql on import,
	// keeping the build cgo-free.
	_ "modernc.org/sqlite"
)

// sqlOpen is sql.Open, extracted as a seam for tests — the sqlite driver
// defers connecting until first use, so sql.Open itself never actually fails.
var sqlOpen = sql.Open

// '?' opens a query string in the sqlite DSN (silently turning a configured
// path into a throwaway in-memory store) and '#' truncates it as a fragment;
// refused by name rather than escaped.
const dsnReservedChars = "?#"

// Runs before sql.Open so a bad path fails at startup, not silently.
func validateDBPath(path string) error {
	i := strings.IndexAny(path, dsnReservedChars)
	if i < 0 {
		return nil
	}
	return fmt.Errorf("lease database path %q may not contain %q", path, path[i:i+1])
}

// RFC 8415 §11: a DUID may take any of four forms, two of them binary, so
// it's stored as a blob rather than text.
func loadDB(path string) (*sql.DB, error) {
	if err := validateDBPath(path); err != nil {
		return nil, err
	}
	db, err := sqlOpen("sqlite", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%T): %w", err, err)
	}
	if _, err := db.Exec("create table if not exists leases6 (duid blob, iaid int, ip text, expiry int, hostname text, primary key (duid, iaid))"); err != nil {
		return nil, fmt.Errorf("table creation failed: %w", err)
	}
	return db, nil
}

// Read big-endian so the stored integer orders the same way the bytes do.
func iaidValue(iaid [4]byte) int64 {
	return int64(binary.BigEndian.Uint32(iaid[:]))
}

// Every field is checked even though this process wrote them — the file is
// a plain sqlite database an operator can edit, and a bad row must stop the
// server, not reach the allocator.
func recordFromRow(duid []byte, iaid int64, ip string, expiry int, hostname string) (*Record, error) {
	if len(duid) == 0 || len(duid) > maxDUIDLen {
		return nil, fmt.Errorf("stored client DUID is %d octets, want 1 to %d", len(duid), maxDUIDLen)
	}
	if iaid < 0 || iaid > math.MaxUint32 {
		return nil, fmt.Errorf("stored IAID %d is outside the 32-bit range", iaid)
	}
	addr := net.ParseIP(ip)
	if addr.To16() == nil || addr.To4() != nil {
		return nil, fmt.Errorf("expected an IPv6 address, got: %v", ip)
	}
	rec := &Record{DUID: duid, IP: addr.To16(), expires: expiry, hostname: hostname}
	// Safe: iaid was bounds-checked against MaxUint32 above.
	binary.BigEndian.PutUint32(rec.IAID[:], uint32(iaid))
	return rec, nil
}

func loadRecords(db *sql.DB) (map[string]*Record, error) {
	rows, err := db.Query("select duid, iaid, ip, expiry, hostname from leases6")
	if err != nil {
		return nil, fmt.Errorf("failed to query leases database: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		duid         []byte
		iaid         int64
		ip, hostname string
		expiry       int
		records      = make(map[string]*Record)
	)
	for rows.Next() {
		if err := rows.Scan(&duid, &iaid, &ip, &expiry, &hostname); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		rec, err := recordFromRow(duid, iaid, ip, expiry, hostname)
		if err != nil {
			return nil, err
		}
		records[rec.key()] = rec
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed lease database row scanning: %w", err)
	}
	return records, nil
}

func (p *pluginState) saveIPAddress(record *Record) error {
	if _, err := p.leasedb.Exec(
		`insert or replace into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)`,
		record.DUID,
		iaidValue(record.IAID),
		record.IP.String(),
		record.expires,
		record.hostname,
	); err != nil {
		return fmt.Errorf("record insert/update failed: %w", err)
	}
	return nil
}

// The address is part of the WHERE clause, so a row already replaced for a
// different address is left alone.
func (p *pluginState) freeIPAddress(record *Record) error {
	if _, err := p.leasedb.Exec(
		`delete from leases6 where duid = ? and iaid = ? and ip = ?`,
		record.DUID,
		iaidValue(record.IAID),
		record.IP.String(),
	); err != nil {
		return fmt.Errorf("record delete failed: %w", err)
	}
	return nil
}

func (p *pluginState) registerBackingDB(filename string) error {
	if p.leasedb != nil {
		return errors.New("cannot swap out a lease database while running")
	}
	// Never closed: plugins are never stopped or unregistered.
	newLeaseDB, err := loadDB(filename)
	if err != nil {
		return fmt.Errorf("failed to open lease database %s: %w", filename, err)
	}
	p.leasedb = newLeaseDB
	return nil
}
