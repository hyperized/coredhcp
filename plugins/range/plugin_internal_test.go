// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

// mockAllocator is a simple mock for testing
type mockAllocator struct {
	mock.Mock
}

func (m *mockAllocator) Allocate(hint net.IPNet) (net.IPNet, error) {
	return m.Called(hint).Get(0).(net.IPNet), nil
}

func (m *mockAllocator) Free(ip net.IPNet) error {
	m.Called(ip)
	return nil
}

type mockFailingAllocator struct {
	mock.Mock
}

func (m *mockFailingAllocator) Allocate(hint net.IPNet) (net.IPNet, error) {
	args := m.Called(hint)
	return args.Get(0).(net.IPNet), args.Error(1)
}

func (m *mockFailingAllocator) Free(ip net.IPNet) error {
	args := m.Called(ip)
	return args.Error(0)
}

// TestSetupRangeAllocatorCreationError substitutes the newIPv4Allocator seam
// to simulate bitmap.NewIPv4Allocator failing. setupRange's own start/end
// validation already guarantees the real allocator constructor can't fail,
// so this is otherwise unreachable through the public API.
func TestSetupRangeAllocatorCreationError(t *testing.T) {
	orig := newIPv4Allocator
	t.Cleanup(func() { newIPv4Allocator = orig })
	newIPv4Allocator = func(net.IP, net.IP) (*bitmap.IPv4Allocator, error) {
		return nil, errors.New("simulated allocator creation failure")
	}

	dbPath := filepath.Join(t.TempDir(), "leases.db")
	_, err := setupRange(dbPath, "10.0.0.1", "10.0.0.5", "1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not create an allocator")
}

func TestHandler4Inform(t *testing.T) {
	pl := pluginState{}

	hwaddr, err := net.ParseMAC("02:00:00:00:00:20")
	require.NoError(t, err)
	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	result, stop := pl.Handler4(req, resp)
	assert.Same(t, resp, result)
	assert.False(t, stop)
	assert.Nil(t, result.YourIPAddr)
}

func TestHandler4NewAllocation(t *testing.T) {
	db, err := loadDB(":memory:")
	require.NoError(t, err)

	mockAlloc := &mockAllocator{}
	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: mockAlloc,
		LeaseTime: time.Hour,
	}

	hwaddr, err := net.ParseMAC("02:00:00:00:00:10")
	require.NoError(t, err)
	wantIP := net.IPv4(10, 0, 0, 10)
	mockAlloc.On("Allocate", net.IPNet{}).Return(net.IPNet{IP: wantIP})

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	req.UpdateOption(dhcpv4.OptHostName("client-a"))
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	result, stop := pl.Handler4(req, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.Equal(t, wantIP.To4(), result.YourIPAddr)

	rec, ok := pl.Recordsv4[hwaddr.String()]
	require.True(t, ok, "the new lease must be tracked in memory")
	assert.Equal(t, "client-a", rec.hostname)

	persisted, err := loadRecords(pl.leasedb)
	require.NoError(t, err)
	prec, ok := persisted[hwaddr.String()]
	require.True(t, ok, "the new lease must be persisted")
	assert.Equal(t, wantIP.To4().String(), prec.IP.String())

	mockAlloc.AssertExpectations(t)
}

func TestHandler4NewAllocationAllocateError(t *testing.T) {
	db, err := loadDB(":memory:")
	require.NoError(t, err)

	mockAlloc := &mockFailingAllocator{}
	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: mockAlloc,
		LeaseTime: time.Hour,
	}

	hwaddr, err := net.ParseMAC("02:00:00:00:00:11")
	require.NoError(t, err)
	mockAlloc.On("Allocate", net.IPNet{}).Return(net.IPNet{}, fmt.Errorf("no addresses left"))

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	result, stop := pl.Handler4(req, resp)
	assert.Nil(t, result)
	assert.True(t, stop)

	_, ok := pl.Recordsv4[hwaddr.String()]
	assert.False(t, ok, "a failed allocation must not create a record")

	mockAlloc.AssertExpectations(t)
	mockAlloc.AssertNotCalled(t, "Free")
}

func TestHandler4NewAllocationSaveError(t *testing.T) {
	db, err := loadDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close()) // force saveIPAddress to fail

	mockAlloc := &mockAllocator{}
	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: mockAlloc,
		LeaseTime: time.Hour,
	}

	hwaddr, err := net.ParseMAC("02:00:00:00:00:12")
	require.NoError(t, err)
	wantIP := net.IPv4(10, 0, 0, 12)
	mockAlloc.On("Allocate", net.IPNet{}).Return(net.IPNet{IP: wantIP})

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	// a storage failure while allocating is only logged; the client still
	// gets its lease for this session.
	result, stop := pl.Handler4(req, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.Equal(t, wantIP.To4(), result.YourIPAddr)

	_, ok := pl.Recordsv4[hwaddr.String()]
	assert.True(t, ok, "the lease is still tracked in memory despite the storage failure")

	mockAlloc.AssertExpectations(t)
}

func TestHandler4RenewalExtendsLease(t *testing.T) {
	db, err := loadDB(":memory:")
	require.NoError(t, err)

	hwaddr, err := net.ParseMAC("02:00:00:00:00:13")
	require.NoError(t, err)
	existing := &Record{
		IP:       net.IPv4(10, 0, 0, 13),
		expires:  int(time.Now().Add(-time.Hour).Unix()), // already expired: due for renewal
		hostname: "old-name",
	}
	pl := pluginState{
		leasedb:   db,
		Recordsv4: map[string]*Record{hwaddr.String(): existing},
		LeaseTime: time.Hour,
	}

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	req.UpdateOption(dhcpv4.OptHostName("new-name"))
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	result, stop := pl.Handler4(req, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.Equal(t, existing.IP, result.YourIPAddr)
	assert.Equal(t, "new-name", pl.Recordsv4[hwaddr.String()].hostname)
	assert.True(t, existing.expires > int(time.Now().Unix()), "the lease expiry must have been pushed out")

	persisted, err := loadRecords(pl.leasedb)
	require.NoError(t, err)
	prec, ok := persisted[hwaddr.String()]
	require.True(t, ok)
	assert.Equal(t, "new-name", prec.hostname)
}

func TestHandler4RenewalSaveError(t *testing.T) {
	db, err := loadDB(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close()) // force saveIPAddress to fail

	hwaddr, err := net.ParseMAC("02:00:00:00:00:14")
	require.NoError(t, err)
	existing := &Record{
		IP:       net.IPv4(10, 0, 0, 14),
		expires:  int(time.Now().Add(-time.Hour).Unix()),
		hostname: "old-name",
	}
	pl := pluginState{
		leasedb:   db,
		Recordsv4: map[string]*Record{hwaddr.String(): existing},
		LeaseTime: time.Hour,
	}

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	// a storage failure while renewing is only logged; the in-memory lease
	// is still extended and returned to the client.
	result, stop := pl.Handler4(req, resp)
	require.NotNil(t, result)
	assert.False(t, stop)
	assert.Equal(t, existing.IP, result.YourIPAddr)
	assert.True(t, existing.expires > int(time.Now().Unix()))
}

func TestHandler4Release(t *testing.T) {
	db, dbErr := testDBSetup()
	if dbErr != nil {
		t.Fatalf("Failed to set up test DB: %v", dbErr)
	}

	mockAlloc := &mockAllocator{}

	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: mockAlloc,
	}

	loadedRecords, loadErr := loadRecords(db)
	if loadErr != nil {
		t.Fatalf("Failed to load records: %v", loadErr)
	}
	pl.Recordsv4 = loadedRecords

	// Create a DHCP RELEASE request using existing test data
	hwaddr, _ := net.ParseMAC(records[1].mac)
	req := &dhcpv4.DHCPv4{
		ClientHWAddr: hwaddr,
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	// Verify record exists before release
	record, exists := pl.Recordsv4[hwaddr.String()]
	assert.True(t, exists, "Record should exist before release")

	expectedIPNet := net.IPNet{IP: record.IP}
	mockAlloc.On("Free", expectedIPNet).Return(nil)

	// Call Handler4 with RELEASE message
	result, stop := pl.Handler4(req, resp)

	assert.Nil(t, result, "Should return nil response for RELEASE")
	assert.True(t, stop, "Should return true to stop processing")

	_, exists = pl.Recordsv4[hwaddr.String()]
	assert.False(t, exists, "Record should be removed from memory after release")

	parsedRecords, parseErr := loadRecords(pl.leasedb)
	if parseErr != nil {
		t.Fatalf("Failed to load records after release: %v", parseErr)
	}
	_, exists = parsedRecords[hwaddr.String()]
	assert.False(t, exists, "Record should be removed from storage after release")

	mockAlloc.AssertExpectations(t)
	mockAlloc.AssertNotCalled(t, "Allocate")
}

func TestHandler4ReleaseAllocatorError(t *testing.T) {
	db, parseErr := testDBSetup()
	if parseErr != nil {
		t.Fatalf("Failed to set up test DB: %v", parseErr)
	}

	mockAlloc := &mockFailingAllocator{}

	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: mockAlloc,
	}

	loadedRecords, err := loadRecords(db)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	pl.Recordsv4 = loadedRecords

	hwaddr, _ := net.ParseMAC(records[1].mac)
	req := &dhcpv4.DHCPv4{
		ClientHWAddr: hwaddr,
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	record := pl.Recordsv4[hwaddr.String()]
	expectedIPNet := net.IPNet{IP: record.IP}

	expectedError := fmt.Errorf("mock allocator free failure")
	mockAlloc.On("Free", expectedIPNet).Return(expectedError)

	// Call Handler4 - this should fail on allocator.Free()
	result, stop := pl.Handler4(req, resp)

	assert.Nil(t, result, "Should return nil on allocator failure")
	assert.True(t, stop, "Should stop processing on allocator failure")

	_, exists := pl.Recordsv4[hwaddr.String()]
	assert.False(t, exists, "Record should be removed from memory even on allocator failure")

	parsedRecords, parseErr := loadRecords(pl.leasedb)
	if parseErr != nil {
		t.Fatalf("Failed to load records after release: %v", parseErr)
	}
	_, exists = parsedRecords[hwaddr.String()]
	assert.False(t, exists, "Record should be removed from storage even on allocator failure")

	mockAlloc.AssertExpectations(t)
	mockAlloc.AssertNotCalled(t, "Allocate")
}

func TestHandler4ReleaseStorageError(t *testing.T) {
	db, parseErr := testDBSetup()
	if parseErr != nil {
		t.Fatalf("Failed to set up test DB: %v", parseErr)
	}

	mockAlloc := &mockAllocator{}

	pl := pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: mockAlloc,
	}

	loadedRecords, err := loadRecords(db)
	if err != nil {
		t.Fatalf("Failed to load records: %v", err)
	}
	pl.Recordsv4 = loadedRecords

	hwaddr, _ := net.ParseMAC(records[1].mac)
	req := &dhcpv4.DHCPv4{
		ClientHWAddr: hwaddr,
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	// Close the database to simulate storage failure
	require.NoError(t, db.Close())

	result, stop := pl.Handler4(req, resp)

	assert.Nil(t, result, "Should return nil on storage failure")
	assert.True(t, stop, "Should stop processing on storage failure")

	_, exists := pl.Recordsv4[hwaddr.String()]
	assert.True(t, exists, "Record should still exist in memory after storage failure")

	mockAlloc.AssertNotCalled(t, "Free")
	mockAlloc.AssertNotCalled(t, "Allocate")
}
