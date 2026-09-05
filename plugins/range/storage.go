// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	// Pure-Go driver, so the build stays cgo-free.
	_ "modernc.org/sqlite"
)

// sqlOpen is a test seam: the sqlite driver implements only driver.Driver, so
// database/sql defers connecting and sql.Open never fails for it.
var sqlOpen = sql.Open

// In the "file:" URI the sqlite driver parses, '?' opens a query string, so
// "leases.db?mode=memory" quietly loses every lease at restart, and '#'
// truncates the name. Refused rather than escaped.
const dsnReservedChars = "?#"

// Runs before sql.Open so a bad path fails at startup instead of producing a
// store that looks like it works.
func validateDBPath(path string) error {
	i := strings.IndexAny(path, dsnReservedChars)
	if i < 0 {
		return nil
	}
	return fmt.Errorf("lease database path %q may not contain %q", path, path[i:i+1])
}

func loadDB(path string) (*sql.DB, error) {
	if err := validateDBPath(path); err != nil {
		return nil, err
	}
	db, err := sqlOpen("sqlite", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%T): %w", err, err)
	}
	if _, err := db.Exec("create table if not exists leases4 (mac string not null, ip string not null, expiry int, hostname string not null, primary key (mac, ip))"); err != nil {
		return nil, fmt.Errorf("table creation failed: %w", err)
	}
	return db, nil
}

func loadRecords(db *sql.DB) (map[string]*Record, error) {
	rows, err := db.Query("select mac, ip, expiry, hostname from leases4")
	if err != nil {
		return nil, fmt.Errorf("failed to query leases database: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		mac, ip, hostname string
		expiry            int
		records           = make(map[string]*Record)
	)
	for rows.Next() {
		if err := rows.Scan(&mac, &ip, &expiry, &hostname); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		hwaddr, err := net.ParseMAC(mac)
		if err != nil {
			return nil, fmt.Errorf("malformed hardware address: %s", mac)
		}
		ipaddr := net.ParseIP(ip)
		if ipaddr.To4() == nil {
			return nil, fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
		}
		records[hwaddr.String()] = &Record{IP: ipaddr, expires: expiry, hostname: hostname}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed lease database row scanning: %w", err)
	}
	return records, nil
}

// mac is the canonical net.HardwareAddr.String() form, which is also the
// Recordsv4 key, so the sweeper never has to reparse and reformat it.
func (p *pluginState) saveIPAddress(mac string, record *Record) error {
	if _, err := p.leasedb.Exec(
		`insert or replace into leases4(mac, ip, expiry, hostname) values (?, ?, ?, ?)`,
		mac,
		record.IP.String(),
		record.expires,
		record.hostname,
	); err != nil {
		return fmt.Errorf("record insert/update failed: %w", err)
	}
	return nil
}

// mac is in the same canonical form as for saveIPAddress.
func (p *pluginState) freeIPAddress(mac string, record *Record) error {
	if _, err := p.leasedb.Exec(
		`delete from leases4 where mac = ? and ip = ?`,
		mac,
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
	// Never closed, because plugins are never stopped or unregistered.
	newLeaseDB, err := loadDB(filename)
	if err != nil {
		return fmt.Errorf("failed to open lease database %s: %w", filename, err)
	}
	p.leasedb = newLeaseDB
	return nil
}
