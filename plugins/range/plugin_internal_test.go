// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
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
	// Still valid, but expiring long before the hour-long lease we are about
	// to advertise, so Handler4 must extend it in place. An already-expired
	// record would instead be reclaimed and re-allocated, which is
	// TestHandler4ExpiredLeaseIsReallocated's job.
	existing := &Record{
		IP:       net.IPv4(10, 0, 0, 13),
		expires:  int(time.Now().Add(time.Minute).Unix()),
		hostname: "old-name",
	}
	expiresBefore := existing.expires
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
	assert.Greater(t, existing.expires, expiresBefore, "the lease expiry must have been pushed out")

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
		expires:  int(time.Now().Add(time.Minute).Unix()), // valid, but due for renewal
		hostname: "old-name",
	}
	expiresBefore := existing.expires
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
	assert.Greater(t, existing.expires, expiresBefore)
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

// fakeClock is a manually advanced clock, so lease lifetimes can be exercised
// without sleeping. It is safe for concurrent use because the background
// sweeper reads it from its own goroutine while the test advances it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// newFakeClock starts on a whole second. Lease expiry is stored with second
// granularity, so this keeps the arithmetic in the tests exact instead of
// leaving sub-second truncation to reason about.
func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testLeaseTime is the lease term every expiry test runs on. The fake clock
// makes the value itself arbitrary, so one shared term keeps the "advance past
// expiry" arithmetic in the tests readable.
const testLeaseTime = time.Hour

// newTestPlugin builds a plugin instance over the inclusive range
// [start, end], backed by a real bitmap allocator, a temp-dir lease database
// and a fake clock. The database is a file rather than ":memory:" so that the
// assertions can read it back over a pooled connection, and so that the
// sweeper goroutine and the test see the same rows.
func newTestPlugin(t *testing.T, start, end net.IP) (*pluginState, *fakeClock) {
	t.Helper()

	db, err := loadDB(filepath.Join(t.TempDir(), "leases.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv4Allocator(start, end)
	require.NoError(t, err)

	clock := newFakeClock()
	return &pluginState{
		leasedb:   db,
		Recordsv4: make(map[string]*Record),
		allocator: alloc,
		LeaseTime: testLeaseTime,
		now:       clock.Now,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}, clock
}

// request drives Handler4 for mac and returns the offered address, or nil when
// the request was dropped.
func request(t *testing.T, pl *pluginState, mac string) net.IP {
	t.Helper()
	hwaddr, err := net.ParseMAC(mac)
	require.NoError(t, err)

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}
	result, _ := pl.Handler4(req, resp)
	if result == nil {
		return nil
	}
	return result.YourIPAddr
}

// leaseRowCount counts a MAC's rows with raw SQL rather than going through
// loadRecords, so an assertion about storage cannot be satisfied by the
// plugin's own view of it. It reports -1 on a query failure instead of failing
// the test, so it is also safe to call from a require.Eventually condition,
// which runs on its own goroutine.
func leaseRowCount(db *sql.DB, mac string) int {
	var n int
	if err := db.QueryRow("select count(*) from leases4 where mac = ?", mac).Scan(&n); err != nil {
		return -1
	}
	return n
}

func TestRecordExpired(t *testing.T) {
	at := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"lapsed an hour ago", at.Add(-time.Hour), true},
		{"lapsing exactly now", at, true},
		{"a second left", at.Add(time.Second), false},
		{"an hour left", at.Add(time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &Record{expires: int(tc.expires.Unix())}
			assert.Equal(t, tc.want, rec.expired(at))
		})
	}
}

func TestTimeNowSeam(t *testing.T) {
	t.Run("defaults to the wall clock", func(t *testing.T) {
		pl := &pluginState{}
		assert.WithinDuration(t, time.Now(), pl.timeNow(), time.Minute)
	})

	t.Run("uses the injected clock", func(t *testing.T) {
		clock := newFakeClock()
		pl := &pluginState{now: clock.Now}
		assert.Equal(t, clock.Now(), pl.timeNow())

		clock.Advance(time.Hour)
		assert.Equal(t, clock.Now(), pl.timeNow())
	})
}

// TestHandler4ExpiredLeaseReclamation is the regression test for upstream
// issues #148 and #182: a single-address pool whose only lease has lapsed must
// be handed out again, whether the original client comes back or a new one
// asks. Before the fix the address stayed allocated forever and the second
// request was dropped.
func TestHandler4ExpiredLeaseReclamation(t *testing.T) {
	const (
		macA = "02:00:00:00:0a:00"
		macB = "02:00:00:00:0a:01"
	)
	for _, tc := range []struct {
		name      string
		second    string
		wantOther string
	}{
		{"the same client returns after its lease lapsed", macA, macB},
		{"a different client takes over the expired address", macB, macA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A pool of exactly one address: nothing can be handed out until
			// the expired lease is actually reclaimed.
			pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))

			leased := request(t, pl, macA)
			require.NotNil(t, leased)
			assert.Equal(t, net.IPv4(10, 0, 0, 1).To4(), leased)

			// While that lease is live the pool really is exhausted, and
			// reclamation must not steal it.
			assert.Nil(t, request(t, pl, macB), "a live lease must not be reclaimed")

			clock.Advance(testLeaseTime + time.Second)

			got := request(t, pl, tc.second)
			require.NotNil(t, got, "the expired address must be available again")
			assert.Equal(t, leased, got)

			require.Len(t, pl.Recordsv4, 1, "only the current holder may be tracked")
			holder, ok := pl.Recordsv4[tc.second]
			require.True(t, ok)
			assert.Equal(t, int(clock.Now().Add(testLeaseTime).Unix()), holder.expires, "the reissued lease runs a full term from now")

			assert.Equal(t, 1, leaseRowCount(pl.leasedb, tc.second), "the new lease must be persisted")
			assert.Equal(t, 0, leaseRowCount(pl.leasedb, tc.wantOther), "the reclaimed lease must be gone from storage")
		})
	}
}

// TestHandler4AllocationSweepsExhaustedPool covers the lazy reclamation path:
// the allocator fails, a sweep frees whatever has lapsed, and the retry
// succeeds. The pool is filled completely so the first attempt cannot succeed.
func TestHandler4AllocationSweepsExhaustedPool(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

	filled := []string{"02:00:00:00:0b:00", "02:00:00:00:0b:01"}
	for _, mac := range filled {
		require.NotNil(t, request(t, pl, mac))
	}
	require.Len(t, pl.Recordsv4, 2)

	// Only the first lease lapses; the second still has half its term left.
	clock.Advance(30 * time.Minute)
	require.NotNil(t, request(t, pl, filled[1]), "renewal keeps the second lease alive")
	clock.Advance(31 * time.Minute)

	got := request(t, pl, "02:00:00:00:0b:02")
	require.NotNil(t, got)
	assert.Equal(t, net.IPv4(10, 0, 0, 1).To4(), got, "the newcomer gets the address freed by the sweep")

	assert.Equal(t, 0, leaseRowCount(pl.leasedb, filled[0]), "the expired lease must be gone from storage")
	assert.Equal(t, 1, leaseRowCount(pl.leasedb, filled[1]), "the live lease must be untouched")
}

// TestHandler4RenewalLeavesFullTermLeaseAlone pins the no-op branch of renew:
// a lease that already outlives the term we are about to advertise is not
// rewritten, so a client hammering DHCPREQUEST does not hammer sqlite.
func TestHandler4RenewalLeavesFullTermLeaseAlone(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

	const mac = "02:00:00:00:0c:00"
	require.NotNil(t, request(t, pl, mac))
	first := *pl.Recordsv4[mac]

	require.NotNil(t, request(t, pl, mac))
	assert.Equal(t, first.expires, pl.Recordsv4[mac].expires, "a full-term lease must not be re-persisted")
}

// TestHandler4ExpiredLeaseStorageFailure covers reclamation failing on the
// renewal path. The row cannot be deleted, so the address is still spoken for
// and must not be handed out again: the client keeps it and the next sweep
// retries.
func TestHandler4ExpiredLeaseStorageFailure(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	mockAlloc := &mockAllocator{}

	const mac = "02:00:00:00:0d:00"
	leased := request(t, pl, mac)
	require.NotNil(t, leased)

	clock.Advance(testLeaseTime + time.Second)
	require.NoError(t, pl.leasedb.Close()) // every statement now fails
	pl.allocator = mockAlloc

	got := request(t, pl, mac)
	require.NotNil(t, got, "the client keeps the address it already had")
	assert.Equal(t, leased, got)

	rec, ok := pl.Recordsv4[mac]
	require.True(t, ok, "a lease that could not be reclaimed stays tracked")
	assert.Equal(t, int(clock.Now().Add(testLeaseTime).Unix()), rec.expires, "it is renewed in place instead")
	mockAlloc.AssertNotCalled(t, "Free")
	mockAlloc.AssertNotCalled(t, "Allocate")
}

func TestSweepExpiredSkipsUndeletableRows(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 4))

	const stuck = "02:00:00:00:0e:00"
	macs := []string{stuck, "02:00:00:00:0e:01", "02:00:00:00:0e:02"}
	for _, mac := range macs {
		require.NotNil(t, request(t, pl, mac))
	}

	// A trigger that refuses to delete one client's row, standing in for any
	// storage failure that hits a single record mid-sweep.
	_, err := pl.leasedb.Exec(fmt.Sprintf(`
		CREATE TRIGGER prevent_delete
		BEFORE DELETE ON leases4
		WHEN OLD.mac = '%s'
		BEGIN
			SELECT RAISE(ABORT, 'deletion blocked');
		END
	`, stuck))
	require.NoError(t, err)

	clock.Advance(testLeaseTime + time.Second)
	assert.Equal(t, 2, pl.sweepExpired(clock.Now()), "the sweep continues past the record it cannot delete")

	require.Len(t, pl.Recordsv4, 1)
	_, ok := pl.Recordsv4[stuck]
	assert.True(t, ok, "the undeletable record stays tracked so its address is not handed out twice")
	assert.Equal(t, 1, leaseRowCount(pl.leasedb, stuck))
}

func TestSweepOnceWithNothingExpired(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

	const mac = "02:00:00:00:0f:00"
	require.NotNil(t, request(t, pl, mac))

	pl.sweepOnce()
	assert.Len(t, pl.Recordsv4, 1, "a live lease survives a sweep")
	assert.Equal(t, 1, leaseRowCount(pl.leasedb, mac))
}

// TestSweeperReclaimsInBackground drives the real ticker at a very short
// interval: without any client asking for an address, an expired lease must
// disappear from the map, the allocator and the database on its own.
func TestSweeperReclaimsInBackground(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))

	const mac = "02:00:00:00:10:00"
	require.NotNil(t, request(t, pl, mac))
	clock.Advance(testLeaseTime + time.Second)

	pl.startSweeper(time.Millisecond)
	t.Cleanup(pl.stopSweeper)

	require.Eventually(t, func() bool {
		pl.Lock()
		defer pl.Unlock()
		return len(pl.Recordsv4) == 0 && leaseRowCount(pl.leasedb, mac) == 0
	}, 5*time.Second, 2*time.Millisecond, "the background sweeper must reclaim the expired lease")

	// Removal from the map alone would not prove reclamation; the address
	// must be allocatable again.
	assert.NotNil(t, request(t, pl, "02:00:00:00:10:01"))
}

func TestDefaultSweepInterval(t *testing.T) {
	for _, tc := range []struct {
		name      string
		leaseTime time.Duration
		want      time.Duration
	}{
		{"half of a long lease", time.Hour, 30 * time.Minute},
		{"half of a short lease", 10 * time.Minute, 5 * time.Minute},
		{"exactly at the floor", time.Minute, minSweepInterval},
		{"below the floor", 5 * time.Second, minSweepInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, defaultSweepInterval(tc.leaseTime))
		})
	}
}

func TestParseSweepInterval(t *testing.T) {
	for _, tc := range []struct {
		name       string
		extra      []string
		want       time.Duration
		wantErrSub string
	}{
		{name: "derived from the lease time", want: 30 * time.Minute},
		{name: "explicit override", extra: []string{"sweep:90s"}, want: 90 * time.Second},
		{name: "unknown argument", extra: []string{"90s"}, wantErrSub: "unexpected argument"},
		{name: "too many arguments", extra: []string{"sweep:90s", "sweep:2m"}, wantErrSub: "too many arguments"},
		{name: "malformed duration", extra: []string{"sweep:soon"}, wantErrSub: "invalid sweep interval"},
		{name: "zero", extra: []string{"sweep:0s"}, wantErrSub: "has to be positive"},
		{name: "negative", extra: []string{"sweep:-1m"}, wantErrSub: "has to be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSweepInterval(time.Hour, tc.extra)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestNewPluginStateStartsIdle pins that construction does not start the
// sweeper: setupRange starts it only once every other step has succeeded.
func TestNewPluginStateStartsIdle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	pl, err := newPluginState(dbPath, "10.0.0.1", "10.0.0.5", "1h", "sweep:90s")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pl.leasedb.Close() })

	assert.Equal(t, 90*time.Second, pl.sweepInterval)
	assert.NotNil(t, pl.now)

	select {
	case <-pl.done:
		t.Fatal("newPluginState must not start the sweeper")
	default:
	}
}
