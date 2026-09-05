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

// Substitutes the newIPv4Allocator seam, since setupRange's own validation guarantees the real constructor can't otherwise fail.
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

	// A storage failure while allocating is only logged; the client still gets its lease.
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
	// Expires soon but not yet, so Handler4 extends it in place rather than reclaiming it (see TestHandler4ExpiredLeaseReclamation).
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

	// A storage failure while renewing is only logged; the lease is extended anyway.
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

	hwaddr, _ := net.ParseMAC(records[1].mac)
	record, exists := pl.Recordsv4[hwaddr.String()]
	assert.True(t, exists, "Record should exist before release")

	// RFC 2131 §4.4.6: the client names the lease it releases in ciaddr.
	req := &dhcpv4.DHCPv4{
		ClientHWAddr: hwaddr,
		ClientIPAddr: record.IP,
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	expectedIPNet := net.IPNet{IP: record.IP}
	mockAlloc.On("Free", expectedIPNet).Return(nil)

	result, stop := pl.Handler4(req, resp)

	assert.Same(t, resp, result, "later plugins must still see the release")
	assert.False(t, stop, "the chain carries on")
	assert.Nil(t, result.YourIPAddr, "a release must not hand out an address")

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
	record := pl.Recordsv4[hwaddr.String()]
	req := &dhcpv4.DHCPv4{
		ClientHWAddr: hwaddr,
		ClientIPAddr: record.IP,
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	expectedIPNet := net.IPNet{IP: record.IP}

	expectedError := fmt.Errorf("mock allocator free failure")
	mockAlloc.On("Free", expectedIPNet).Return(expectedError)

	result, stop := pl.Handler4(req, resp)

	assert.Same(t, resp, result, "a failed release is still passed down the chain")
	assert.False(t, stop, "the chain carries on")

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
		ClientIPAddr: pl.Recordsv4[hwaddr.String()].IP,
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))

	resp := &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)}

	require.NoError(t, db.Close())

	result, stop := pl.Handler4(req, resp)

	assert.Same(t, resp, result, "a failed release is still passed down the chain")
	assert.False(t, stop, "the chain carries on")

	_, exists := pl.Recordsv4[hwaddr.String()]
	assert.True(t, exists, "Record should still exist in memory after storage failure")

	mockAlloc.AssertNotCalled(t, "Free")
	mockAlloc.AssertNotCalled(t, "Allocate")
}

// fakeClock lets lease lifetimes advance without sleeping; safe for concurrent use since the sweeper goroutine reads it while tests advance it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// Starts on a whole second, matching lease expiry's second-granularity storage, so the tests' arithmetic stays exact.
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

// The value is arbitrary since the fake clock drives expiry; one shared term just keeps the tests' arithmetic readable.
const testLeaseTime = time.Hour

// Uses a file-backed db, not ":memory:", so the sweeper goroutine and the test's assertions see the same rows over a pooled connection.
func newTestPlugin(t *testing.T, start, end net.IP) (*pluginState, *fakeClock) {
	t.Helper()

	db, err := loadDB(filepath.Join(t.TempDir(), "leases.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv4Allocator(start, end)
	require.NoError(t, err)

	clock := newFakeClock()
	return &pluginState{
		leasedb:          db,
		Recordsv4:        make(map[string]*Record),
		declined:         make(map[string]time.Time),
		allocator:        alloc,
		LeaseTime:        testLeaseTime,
		poolSize:         poolSize(start, end),
		declineProbation: defaultDeclineProbation,
		declineMax:       defaultDeclineMax(poolSize(start, end)),
		now:              clock.Now,
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
	}, clock
}

// release drives a DHCPRELEASE from mac; a nil ciaddr means no address was named.
func release(t *testing.T, pl *pluginState, mac string, ciaddr net.IP) (*dhcpv4.DHCPv4, bool) {
	t.Helper()
	hwaddr, err := net.ParseMAC(mac)
	require.NoError(t, err)

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr, ClientIPAddr: ciaddr}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))
	return pl.Handler4(req, &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)})
}

// decline drives a DHCPDECLINE from mac; a nil addr leaves option 50 off entirely.
func decline(t *testing.T, pl *pluginState, mac string, addr net.IP) (*dhcpv4.DHCPv4, bool) {
	t.Helper()
	hwaddr, err := net.ParseMAC(mac)
	require.NoError(t, err)

	req := &dhcpv4.DHCPv4{ClientHWAddr: hwaddr}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	if addr != nil {
		req.UpdateOption(dhcpv4.OptRequestedIPAddress(addr))
	}
	return pl.Handler4(req, &dhcpv4.DHCPv4{Options: make(dhcpv4.Options)})
}

// request drives Handler4 for mac and returns the offered address, or nil if dropped.
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

// Uses raw SQL so assertions aren't just checking the plugin's own view; returns -1 on error so it's safe to call from a require.Eventually goroutine.
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

// Regression test for upstream issues #148 and #182: a single-address pool must hand out its only lease again once it lapses.
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
			// A pool of exactly one address forces reclamation before anything can be handed out.
			pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))

			leased := request(t, pl, macA)
			require.NotNil(t, leased)
			assert.Equal(t, net.IPv4(10, 0, 0, 1).To4(), leased)

			// While the lease is live, reclamation must not steal it out from under the holder.
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

// The pool is filled completely so the first allocation attempt fails; a sweep frees what's lapsed for the retry.
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

// A lease that already outlives the advertised term isn't rewritten, so a client hammering DHCPREQUEST doesn't hammer sqlite.
func TestHandler4RenewalLeavesFullTermLeaseAlone(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

	const mac = "02:00:00:00:0c:00"
	require.NotNil(t, request(t, pl, mac))
	first := *pl.Recordsv4[mac]

	require.NotNil(t, request(t, pl, mac))
	assert.Equal(t, first.expires, pl.Recordsv4[mac].expires, "a full-term lease must not be re-persisted")
}

// The row can't be deleted, so the address stays spoken for; the client keeps it and the next sweep retries.
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

	// Stands in for any storage failure that hits a single record mid-sweep.
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

// Drives the real ticker at a short interval: with no client asking, an expired lease must vanish on its own.
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

	// Removal from the map alone wouldn't prove reclamation; the address must be allocatable again.
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

func TestParseOptions(t *testing.T) {
	// One representative pool size keeps the table readable; testPoolSize is big enough for a tenth of it to clear the floor of one.
	const testPoolSize = 100

	for _, tc := range []struct {
		name          string
		poolSize      uint64
		extra         []string
		wantSweep     time.Duration
		wantProbation time.Duration
		wantMax       int
		wantErrSub    string
	}{
		{name: "all derived from defaults", wantSweep: 30 * time.Minute, wantProbation: defaultDeclineProbation, wantMax: 10},
		{name: "a pool too small for a tenth keeps one address back", poolSize: 4, wantSweep: 30 * time.Minute, wantProbation: defaultDeclineProbation, wantMax: 1},
		{name: "a pool big enough to hit the cap", poolSize: 1 << 32, wantSweep: 30 * time.Minute, wantProbation: defaultDeclineProbation, wantMax: maxDeclineQuarantine},
		{name: "sweep override", extra: []string{"sweep:90s"}, wantSweep: 90 * time.Second, wantProbation: defaultDeclineProbation, wantMax: 10},
		{name: "probation override", extra: []string{"decline-probation:15m"}, wantSweep: 30 * time.Minute, wantProbation: 15 * time.Minute, wantMax: 10},
		{name: "probation disabled", extra: []string{"decline-probation:0"}, wantSweep: 30 * time.Minute, wantMax: 10},
		{name: "quarantine override", extra: []string{"decline-max:3"}, wantSweep: 30 * time.Minute, wantProbation: defaultDeclineProbation, wantMax: 3},
		{name: "quarantine disabled", extra: []string{"decline-max:0"}, wantSweep: 30 * time.Minute, wantProbation: defaultDeclineProbation},
		{name: "both, sweep first", extra: []string{"sweep:90s", "decline-probation:15m"}, wantSweep: 90 * time.Second, wantProbation: 15 * time.Minute, wantMax: 10},
		{name: "both, probation first", extra: []string{"decline-probation:15m", "sweep:90s"}, wantSweep: 90 * time.Second, wantProbation: 15 * time.Minute, wantMax: 10},
		{name: "all three, in reverse", extra: []string{"decline-max:2", "decline-probation:15m", "sweep:90s"}, wantSweep: 90 * time.Second, wantProbation: 15 * time.Minute, wantMax: 2},
		{name: "bare duration left over from the positional args", extra: []string{"90s"}, wantErrSub: "unexpected argument"},
		{name: "a key with no value", extra: []string{"sweep"}, wantErrSub: "unexpected argument"},
		{name: "unknown key", extra: []string{"reap:90s"}, wantErrSub: "unexpected argument"},
		{name: "sweep given twice", extra: []string{"sweep:90s", "sweep:2m"}, wantErrSub: "sweep given more than once"},
		{name: "probation given twice", extra: []string{"decline-probation:1h", "decline-probation:2h"}, wantErrSub: "decline-probation given more than once"},
		{name: "quarantine given twice", extra: []string{"decline-max:2", "decline-max:3"}, wantErrSub: "decline-max given more than once"},
		{name: "malformed sweep duration", extra: []string{"sweep:soon"}, wantErrSub: "invalid sweep interval"},
		{name: "zero sweep", extra: []string{"sweep:0s"}, wantErrSub: "has to be positive"},
		{name: "negative sweep", extra: []string{"sweep:-1m"}, wantErrSub: "has to be positive"},
		{name: "malformed probation duration", extra: []string{"decline-probation:never"}, wantErrSub: "invalid decline probation"},
		{name: "negative probation", extra: []string{"decline-probation:-1h"}, wantErrSub: "cannot be negative"},
		{name: "malformed quarantine size", extra: []string{"decline-max:lots"}, wantErrSub: "invalid decline maximum"},
		{name: "fractional quarantine size", extra: []string{"decline-max:1.5"}, wantErrSub: "invalid decline maximum"},
		{name: "negative quarantine size", extra: []string{"decline-max:-1"}, wantErrSub: "cannot be negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			size := tc.poolSize
			if size == 0 {
				size = testPoolSize
			}
			got, err := parseOptions(time.Hour, size, tc.extra)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantSweep, got.sweepInterval)
			assert.Equal(t, tc.wantProbation, got.declineProbation)
			assert.Equal(t, tc.wantMax, got.declineMax)
		})
	}
}

// The whole address space is 2^32 addresses, which wraps to zero if the increment happens in uint32 rather than a wider type.
func TestPoolSize(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end net.IP
		want       uint64
	}{
		{name: "one address", start: net.IPv4(10, 0, 0, 1), end: net.IPv4(10, 0, 0, 1), want: 1},
		{name: "a typical pool", start: net.IPv4(10, 0, 0, 100), end: net.IPv4(10, 0, 0, 200), want: 101},
		{name: "a /24", start: net.IPv4(192, 0, 2, 0), end: net.IPv4(192, 0, 2, 255), want: 256},
		{name: "the whole address space", start: net.IPv4(0, 0, 0, 0), end: net.IPv4(255, 255, 255, 255), want: 1 << 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, poolSize(tc.start, tc.end))
		})
	}
}

// setupRange starts the sweeper only once every other step has succeeded.
func TestNewPluginStateStartsIdle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases.db")
	pl, err := newPluginState(dbPath, "10.0.0.1", "10.0.0.5", "1h", "sweep:90s")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pl.leasedb.Close() })

	assert.Equal(t, 90*time.Second, pl.sweepInterval)
	assert.Equal(t, defaultDeclineProbation, pl.declineProbation)
	assert.NotNil(t, pl.declined)
	assert.NotNil(t, pl.now)

	select {
	case <-pl.done:
		t.Fatal("newPluginState must not start the sweeper")
	default:
	}
}

// Regression test for a forged release: it must never fall through to the allocation path and consume an address.
func TestHandler4ReleaseFromUnknownMAC(t *testing.T) {
	const poolSize = 11
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, poolSize))

	for i := range 1000 {
		resp, stop := release(t, pl, fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&0xff), net.IPv4(10, 0, 0, 1))
		require.NotNil(t, resp, "later plugins must still see the release")
		require.False(t, stop)
		require.Nil(t, resp.YourIPAddr, "a release must never hand out an address")
	}

	assert.Empty(t, pl.Recordsv4, "no lease may have been created")

	// Removal from the map alone wouldn't prove the pool is intact, so serve every address it has.
	for i := range poolSize {
		require.NotNil(t, request(t, pl, fmt.Sprintf("02:00:00:01:00:%02x", i)), "the pool must be untouched")
	}
}

// RFC 2131 §4.4.6 has the client name the lease it releases in ciaddr, so a release naming anything else changes nothing.
func TestHandler4ReleaseWrongAddress(t *testing.T) {
	const (
		holder    = "02:00:00:00:11:00"
		neighbour = "02:00:00:00:11:01"
	)
	for _, tc := range []struct {
		name   string
		ciaddr net.IP
	}{
		{"the address a different client holds", net.IPv4(10, 0, 0, 2)},
		{"an address nobody holds", net.IPv4(10, 0, 0, 9)},
		{"no ciaddr at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

			leased := request(t, pl, holder)
			require.NotNil(t, leased)
			neighbourIP := request(t, pl, neighbour)
			require.NotNil(t, neighbourIP)

			resp, stop := release(t, pl, holder, tc.ciaddr)
			require.NotNil(t, resp)
			assert.False(t, stop)

			rec, ok := pl.Recordsv4[holder]
			require.True(t, ok, "the lease must survive a release naming the wrong address")
			assert.Equal(t, leased, rec.IP)
			assert.Equal(t, 1, leaseRowCount(pl.leasedb, holder))
			assert.Equal(t, 1, leaseRowCount(pl.leasedb, neighbour), "and so must the neighbour's")
		})
	}
}

// The response is handed on so a lease hook further down the chain still sees the release.
func TestHandler4ReleaseFreesTheNamedLease(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))

	const mac = "02:00:00:00:12:00"
	leased := request(t, pl, mac)
	require.NotNil(t, leased)

	resp, stop := release(t, pl, mac, leased)
	require.NotNil(t, resp, "later plugins must still see the release")
	assert.False(t, stop)
	assert.Nil(t, resp.YourIPAddr)

	assert.Empty(t, pl.Recordsv4)
	assert.Equal(t, 0, leaseRowCount(pl.leasedb, mac))
	assert.NotNil(t, request(t, pl, "02:00:00:00:12:01"), "the address must be back in the pool")
}

// The pool holds a spare address on purpose: giving way to a client with nowhere else to go is TestAllocateEvictsTheOldestQuarantine's job.
func TestHandler4DeclineQuarantinesTheAddress(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))

	const (
		conflicted = "02:00:00:00:13:00"
		newcomer   = "02:00:00:00:13:01"
		latecomer  = "02:00:00:00:13:02"
	)
	leased := request(t, pl, conflicted)
	require.NotNil(t, leased)

	resp, stop := decline(t, pl, conflicted, leased)
	require.NotNil(t, resp, "later plugins must still see the decline")
	assert.False(t, stop)
	assert.Nil(t, resp.YourIPAddr, "a decline must not hand out an address")

	assert.Empty(t, pl.Recordsv4, "the declined lease is dropped")
	assert.Equal(t, 0, leaseRowCount(pl.leasedb, conflicted), "and its row with it")
	require.Len(t, pl.declined, 1, "but the address stays out of the pool")

	other := request(t, pl, newcomer)
	require.NotNil(t, other)
	assert.NotEqual(t, leased, other, "the next client is given the spare, not the conflict")

	clock.Advance(defaultDeclineProbation + time.Second)
	pl.sweepOnce()
	assert.Empty(t, pl.declined, "probation has run out")

	got := request(t, pl, latecomer)
	require.NotNil(t, got, "the address must be back in the pool")
	assert.Equal(t, leased, got)
}

func TestHandler4DeclineWithoutProbation(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))
	pl.declineProbation = 0

	const mac = "02:00:00:00:14:00"
	leased := request(t, pl, mac)
	require.NotNil(t, leased)

	_, stop := decline(t, pl, mac, leased)
	assert.False(t, stop)
	assert.Empty(t, pl.Recordsv4)
	assert.Empty(t, pl.declined, "nothing is quarantined")
	assert.Equal(t, 0, leaseRowCount(pl.leasedb, mac))

	got := request(t, pl, "02:00:00:00:14:01")
	require.NotNil(t, got, "the address is available immediately")
	assert.Equal(t, leased, got)
}

func TestHandler4DeclineChangesNothing(t *testing.T) {
	const (
		holder   = "02:00:00:00:15:00"
		stranger = "02:00:00:00:15:01"
	)
	for _, tc := range []struct {
		name     string
		mac      string
		declined net.IP
	}{
		{"an address the client does not hold", holder, net.IPv4(10, 0, 0, 2)},
		{"no option 50 at all", holder, nil},
		{"a client with no lease", stranger, net.IPv4(10, 0, 0, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
			leased := request(t, pl, holder)
			require.NotNil(t, leased)

			resp, stop := decline(t, pl, tc.mac, tc.declined)
			require.NotNil(t, resp)
			assert.False(t, stop)
			assert.Nil(t, resp.YourIPAddr, "a decline must never allocate")

			assert.Len(t, pl.Recordsv4, 1, "the existing lease is untouched")
			assert.Empty(t, pl.declined, "nothing is quarantined")
			assert.Equal(t, 1, leaseRowCount(pl.leasedb, holder))
		})
	}
}

// Both quarantine branches persist to storage first, so a restart can't reissue an address already reported as conflicted.
func TestHandler4DeclineStorageFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		probation time.Duration
	}{
		{"with a probation period", defaultDeclineProbation},
		{"with probation disabled", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
			pl.declineProbation = tc.probation

			const mac = "02:00:00:00:16:00"
			leased := request(t, pl, mac)
			require.NotNil(t, leased)
			require.NoError(t, pl.leasedb.Close()) // every statement now fails

			_, stop := decline(t, pl, mac, leased)
			assert.False(t, stop)
			assert.Len(t, pl.Recordsv4, 1, "a lease we cannot forget on disk stays tracked")
			assert.Empty(t, pl.declined)
		})
	}
}

// An address the allocator refuses to free stays parked for the next sweep, rather than leaking the bit for good.
func TestSweepDeclinedKeepsUnfreeableAddresses(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	mockAlloc := &mockFailingAllocator{}
	pl.allocator = mockAlloc

	const ip = "10.0.0.1"
	pl.declined[ip] = clock.Now().Add(-time.Second)
	mockAlloc.On("Free", net.IPNet{IP: net.ParseIP(ip)}).Return(errors.New("simulated double free"))

	assert.Equal(t, 0, pl.sweepDeclined(clock.Now()))
	assert.Len(t, pl.declined, 1, "the address stays parked for the next sweep")
	mockAlloc.AssertExpectations(t)
}

// Regression for the starvation a bounded quarantine prevents: unauthenticated DISCOVER+DECLINE pairs must not be able to exhaust the pool.
func TestDeclineFloodLeavesThePoolServing(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 11))

	const poolAddresses = 11
	require.EqualValues(t, poolAddresses, pl.poolSize)
	require.Equal(t, 1, pl.declineMax, "a tenth of eleven addresses floors at one")

	packets := 0
	for i := range poolAddresses {
		mac := fmt.Sprintf("02:00:00:00:20:%02x", i)
		offered := request(t, pl, mac)
		packets++
		require.NotNil(t, offered, "the pool must keep offering under the flood")
		decline(t, pl, mac, offered)
		packets++
	}
	assert.Equal(t, 2*poolAddresses, packets)
	assert.Len(t, pl.declined, pl.declineMax, "only the bound is held back")
	assert.Empty(t, pl.Recordsv4, "and the flood is left holding no lease")

	// What the flood couldn't quarantine is still allocatable, without the quarantine giving way for it.
	for i := range poolAddresses - pl.declineMax {
		require.NotNil(t, request(t, pl, fmt.Sprintf("02:00:00:00:21:%02x", i)), "a real client must still be served")
	}
	assert.Len(t, pl.Recordsv4, poolAddresses-pl.declineMax)
	assert.Len(t, pl.declined, pl.declineMax, "the quarantine held through all of it")
}

// With every address leased or in probation, the address held back longest goes to the client instead of turning it away.
func TestAllocateEvictsTheOldestQuarantine(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 3))
	pl.declineMax = 2

	const (
		firstDecliner  = "02:00:00:00:22:00"
		secondDecliner = "02:00:00:00:22:01"
		holder         = "02:00:00:00:22:02"
		newcomer       = "02:00:00:00:22:03"
	)

	first := request(t, pl, firstDecliner)
	require.NotNil(t, first)
	decline(t, pl, firstDecliner, first)

	// Separate the two probations in time, so "oldest" means something.
	clock.Advance(time.Minute)

	second := request(t, pl, secondDecliner)
	require.NotNil(t, second)
	decline(t, pl, secondDecliner, second)
	require.Len(t, pl.declined, 2)

	require.NotNil(t, request(t, pl, holder), "the last free address goes to a client that keeps it")

	got := request(t, pl, newcomer)
	require.NotNil(t, got, "an exhausted pool gives up a quarantine rather than a client")
	assert.Equal(t, first, got, "the address held back longest is the one evicted")
	assert.Len(t, pl.declined, 1)
	assert.Contains(t, pl.declined, second.String(), "the more recent quarantine is left alone")
}

// Unlike TestHandler4DeclineWithoutProbation, a probation period is configured here — decline-max:0 alone must still skip the quarantine.
func TestHandler4DeclineMaxZero(t *testing.T) {
	pl, _ := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 1))
	pl.declineMax = 0
	require.NotZero(t, pl.declineProbation, "decline-max is what disables the quarantine here")

	const mac = "02:00:00:00:23:00"
	leased := request(t, pl, mac)
	require.NotNil(t, leased)

	_, stop := decline(t, pl, mac, leased)
	assert.False(t, stop)
	assert.Empty(t, pl.declined, "nothing is quarantined")
	assert.Empty(t, pl.Recordsv4)

	got := request(t, pl, "02:00:00:00:23:01")
	require.NotNil(t, got, "the address is available immediately")
	assert.Equal(t, leased, got)
}

// Same invariant as sweepDeclined: an unfreeable address stays parked rather than leaking the bit for the life of the process.
func TestEvictOldestDeclinedKeepsUnfreeableAddresses(t *testing.T) {
	pl, clock := newTestPlugin(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	mockAlloc := &mockFailingAllocator{}
	pl.allocator = mockAlloc

	const ip = "10.0.0.1"
	pl.declined[ip] = clock.Now().Add(time.Hour)
	mockAlloc.On("Free", net.IPNet{IP: net.ParseIP(ip)}).Return(errors.New("simulated double free"))

	assert.False(t, pl.evictOldestDeclined())
	assert.Len(t, pl.declined, 1, "the address stays parked for the next sweep")
	mockAlloc.AssertExpectations(t)
}
