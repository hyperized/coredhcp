// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package range6

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/coredhcp/coredhcp/plugins/allocators/bitmap"
)

const (
	poolFirst = "2001:db8:1::100"
	poolLast  = "2001:db8:1::1ff"

	// testLeaseTime is the lease term every expiry test runs on. The fake
	// clock makes the value itself arbitrary, so one shared term keeps the
	// "advance past expiry" arithmetic in the tests readable.
	testLeaseTime = time.Hour
)

var (
	duidA = []byte{0xaa, 0x00, 0x00, 0x00, 0x00, 0x01}
	duidB = []byte{0xaa, 0x00, 0x00, 0x00, 0x00, 0x02}
	iaidX = [4]byte{0x00, 0x00, 0x00, 0x01}
)

// mockAllocator is an allocator whose Allocate call always succeeds with
// whatever net.IPNet the test set up, and whose Free never fails.
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

// mockFailingAllocator is an allocator whose calls return whatever error the
// test configured, used to drive the failure branches a real bitmap
// allocator can't be made to hit deterministically.
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

// fakeClock is a manually advanced clock, so lease lifetimes can be
// exercised without sleeping. Safe for concurrent use because the
// background sweeper reads it from its own goroutine while a test advances
// it.
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

// newTestPluginState builds a plugin instance over the inclusive range
// [first, last], backed by a real bitmap allocator, an in-memory lease
// database and a fake clock the test can drive without sleeping.
func newTestPluginState(t *testing.T, first, last net.IP) (*pluginState, *fakeClock) {
	t.Helper()

	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv6Allocator(first, last)
	require.NoError(t, err)

	clock := newFakeClock()
	return &pluginState{
		leasedb:          db,
		Records6:         make(map[string]*Record),
		declined:         make(map[string]time.Time),
		allocator:        alloc,
		LeaseTime:        testLeaseTime,
		declineProbation: defaultDeclineProbation,
		declineMax:       10,
		now:              clock.Now,
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
	}, clock
}

func TestTimeNowSeam(t *testing.T) {
	t.Run("defaults to the wall clock", func(t *testing.T) {
		p := &pluginState{}
		assert.WithinDuration(t, time.Now(), p.timeNow(), time.Minute)
	})

	t.Run("uses the injected clock", func(t *testing.T) {
		clock := newFakeClock()
		p := &pluginState{now: clock.Now}
		assert.Equal(t, clock.Now(), p.timeNow())

		clock.Advance(time.Hour)
		assert.Equal(t, clock.Now(), p.timeNow())
	})
}

// TestClientHostname covers the paths a request's own FQDN option, rather
// than the whole Handler6 pipeline, drives: no option at all, an option with
// no name in it, and a name long enough to trip the RFC 1035 truncation.
// Filtering itself is already pinned end to end by
// TestStoredHostnameIsSanitised.
func TestClientHostname(t *testing.T) {
	longLabels := []string{
		strings.Repeat("a", 60),
		strings.Repeat("b", 60),
		strings.Repeat("c", 60),
		strings.Repeat("d", 60),
		strings.Repeat("e", 60),
	}
	longJoined := strings.Join(longLabels, ".")
	require.Greater(t, len(longJoined), maxHostnameLen, "test fixture must actually exceed the limit")

	for _, tc := range []struct {
		name string
		fqdn *dhcpv6.OptFQDN
		want string
	}{
		{"no FQDN option at all", nil, ""},
		{"FQDN option with no domain name", &dhcpv6.OptFQDN{}, ""},
		{"a name past the RFC 1035 limit is truncated", &dhcpv6.OptFQDN{DomainName: &rfc1035label.Labels{Labels: longLabels}}, longJoined[:maxHostnameLen]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := dhcpv6.NewMessage()
			require.NoError(t, err)
			if tc.fqdn != nil {
				msg.AddOption(tc.fqdn)
			}
			assert.Equal(t, tc.want, clientHostname(msg))
		})
	}
}

// TestOnLink covers the address shapes bytes.Compare can't be handed
// directly: onLink must reject anything that is neither a 4- nor a 16-byte
// address before it ever compares it against the pool bounds.
func TestOnLink(t *testing.T) {
	p := &pluginState{first: net.ParseIP(poolFirst).To16(), last: net.ParseIP(poolLast).To16()}
	for _, tc := range []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"inside the pool", net.ParseIP("2001:db8:1::150"), true},
		{"below the pool", net.ParseIP("2001:db8:1::ff"), false},
		{"above the pool", net.ParseIP("2001:db8:1::200"), false},
		{"neither a 4- nor a 16-byte address", net.IP{1, 2, 3}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, p.onLink(tc.ip))
		})
	}
}

// TestExtendReturnsNoAddrsAvailWhenNothingCanBeReclaimed covers extend's
// rec == nil branch: the binding had lapsed, but there was nothing left to
// give the client back, which the allocator itself can't be made to do
// through a real bitmap without a lot of setup, so a failing mock stands in.
func TestExtendReturnsNoAddrsAvailWhenNothingCanBeReclaimed(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	mockAlloc := &mockFailingAllocator{}
	mockAlloc.On("Free", mock.Anything).Return(nil)
	mockAlloc.On("Allocate", mock.Anything).Return(net.IPNet{}, errors.New("no addresses left"))

	now := time.Now()
	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100"), expires: now.Add(-time.Hour).Unix()}
	p := &pluginState{
		leasedb:   db,
		Records6:  map[string]*Record{rec.key(): rec},
		declined:  make(map[string]time.Time),
		allocator: mockAlloc,
		LeaseTime: testLeaseTime,
	}

	ia := &dhcpv6.OptIANA{IaId: iaidX}
	answer := p.extend(duidA, ia, "", now)
	require.NotNil(t, answer)
	status := answer.Options.Status()
	require.NotNil(t, status)
	assert.Equal(t, dhcpIana.StatusNoAddrsAvail, status.StatusCode)
	mockAlloc.AssertExpectations(t)
}

// TestReallocateExpiredKeepsAddressForLateClient is reallocateExpired's
// success path: a client that comes back after its binding lapsed, but
// before anyone else took the address, gets it back through the allocator
// hint.
func TestReallocateExpiredKeepsAddressForLateClient(t *testing.T) {
	p, clock := newTestPluginState(t, net.ParseIP(poolFirst), net.ParseIP(poolLast))
	key := leaseKey(duidA, iaidX)

	rec := p.allocateLease(key, duidA, iaidX, net.IPNet{}, "old-name", clock.Now())
	require.NotNil(t, rec)
	originalIP := rec.IP
	rec.expires = clock.Now().Add(-time.Second).Unix()

	got, found := p.renewKnown(key, "new-name", clock.Now())
	require.True(t, found)
	require.NotNil(t, got)
	assert.True(t, got.IP.Equal(originalIP), "the same address must come back")
	assert.Equal(t, "new-name", got.hostname)
	assert.Equal(t, clock.Now().Add(testLeaseTime).Unix(), got.expires)
}

// TestReallocateExpiredReleaseLeaseFailureKeepsClientOnOldRecord covers the
// fallback of reallocateExpired: when the stale binding can't be forgotten on
// disk, re-allocating would risk handing the address to a second client, so
// the caller is left on its old record instead.
func TestReallocateExpiredReleaseLeaseFailureKeepsClientOnOldRecord(t *testing.T) {
	p, clock := newTestPluginState(t, net.ParseIP(poolFirst), net.ParseIP(poolLast))
	key := leaseKey(duidA, iaidX)

	rec := p.allocateLease(key, duidA, iaidX, net.IPNet{}, "old-name", clock.Now())
	require.NotNil(t, rec)
	rec.expires = clock.Now().Add(-time.Second).Unix()
	require.NoError(t, p.leasedb.Close()) // every statement now fails

	got, found := p.renewKnown(key, "new-name", clock.Now())
	require.True(t, found)
	require.Same(t, rec, got, "the client must be left on its old record")
	assert.Equal(t, clock.Now().Add(testLeaseTime).Unix(), got.expires, "it is renewed in place instead")
	assert.Same(t, rec, p.Records6[key])
}

// TestAllocateLeaseSaveIPAddressFailureRefusesTheBinding covers a storage
// failure on the new-binding path. The client gets nothing: an address we
// could not write down reads as free after a restart, and the next client to
// ask would be handed the one this client thinks it holds.
func TestAllocateLeaseSaveIPAddressFailureRefusesTheBinding(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close()) // force saveIPAddress to fail

	alloc, err := bitmap.NewIPv6Allocator(net.ParseIP(poolFirst), net.ParseIP(poolLast))
	require.NoError(t, err)

	p := &pluginState{leasedb: db, Records6: make(map[string]*Record), allocator: alloc, LeaseTime: testLeaseTime}
	key := leaseKey(duidA, iaidX)

	assert.Nil(t, p.allocateLease(key, duidA, iaidX, net.IPNet{}, "client-a", time.Now()))
	assert.Empty(t, p.Records6, "an unrecorded binding must not be tracked in memory either")

	// The address went back, so the whole pool is still there to hand out.
	first, err := alloc.Allocate(net.IPNet{})
	require.NoError(t, err)
	assert.Equal(t, poolFirst, first.IP.String())
}

// TestAllocateRetrySucceedsAfterReclaimingExpired covers allocate's first
// retry path: the allocator has nothing left, but a lapsed binding frees up
// exactly enough room for the retry to succeed.
func TestAllocateRetrySucceedsAfterReclaimingExpired(t *testing.T) {
	p, clock := newTestPluginState(t, net.ParseIP("2001:db8:1::100"), net.ParseIP("2001:db8:1::101"))

	rec1 := p.allocateLease(leaseKey(duidA, iaidX), duidA, iaidX, net.IPNet{}, "", clock.Now())
	require.NotNil(t, rec1)
	rec2 := p.allocateLease(leaseKey(duidB, iaidX), duidB, iaidX, net.IPNet{}, "", clock.Now())
	require.NotNil(t, rec2)

	// Only the first binding has lapsed; the second is untouched.
	rec1.expires = clock.Now().Add(-time.Second).Unix()

	ip, err := p.allocate(net.IPNet{})
	require.NoError(t, err)
	assert.True(t, ip.IP.Equal(rec1.IP), "the reclaimed address must be the one handed back")
	_, stillTracked := p.Records6[leaseKey(duidA, iaidX)]
	assert.False(t, stillTracked, "the stale binding is gone once reclaimed")
}

// TestAllocateRetrySucceedsAfterEvictingOldestDeclined covers allocate's
// second retry path: nothing has expired, so the address that has been
// quarantined longest is the one that gives the retry room.
func TestAllocateRetrySucceedsAfterEvictingOldestDeclined(t *testing.T) {
	p, clock := newTestPluginState(t, net.ParseIP("2001:db8:1::100"), net.ParseIP("2001:db8:1::101"))

	rec1 := p.allocateLease(leaseKey(duidA, iaidX), duidA, iaidX, net.IPNet{}, "", clock.Now())
	require.NotNil(t, rec1)
	quarantinedIP := rec1.IP
	rec2 := p.allocateLease(leaseKey(duidB, iaidX), duidB, iaidX, net.IPNet{}, "", clock.Now())
	require.NotNil(t, rec2)

	require.NoError(t, p.quarantine(rec1, clock.Now()))
	require.Len(t, p.declined, 1)

	ip, err := p.allocate(net.IPNet{})
	require.NoError(t, err)
	assert.True(t, ip.IP.Equal(quarantinedIP), "the evicted quarantined address must come back first")
	assert.Empty(t, p.declined, "the entry is dropped once evicted")
}

// TestAllocateGivesUpWhenNothingCanBeReclaimed covers the path where neither
// reclamation trick frees anything: a full pool with no lapsed binding and no
// quarantined address must fail the allocation outright.
func TestAllocateGivesUpWhenNothingCanBeReclaimed(t *testing.T) {
	p, clock := newTestPluginState(t, net.ParseIP("2001:db8:1::100"), net.ParseIP("2001:db8:1::101"))

	require.NotNil(t, p.allocateLease(leaseKey(duidA, iaidX), duidA, iaidX, net.IPNet{}, "", clock.Now()))
	require.NotNil(t, p.allocateLease(leaseKey(duidB, iaidX), duidB, iaidX, net.IPNet{}, "", clock.Now()))

	_, err := p.allocate(net.IPNet{})
	assert.Error(t, err)
}

// TestRenewSaveIPAddressFailureStillExtendsInMemory covers renew's storage
// failure: the in-memory binding is extended and handed to the client
// regardless, with only the log recording that it wasn't persisted.
func TestRenewSaveIPAddressFailureStillExtendsInMemory(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	p := &pluginState{leasedb: db, LeaseTime: testLeaseTime}
	now := time.Now()
	rec := &Record{expires: now.Add(time.Minute).Unix(), hostname: "old-name"}

	p.renew(rec, "new-name", now)
	assert.Equal(t, "new-name", rec.hostname)
	assert.Equal(t, now.Add(testLeaseTime).Round(time.Second).Unix(), rec.expires)
}

// TestRenewLeavesFullTermBindingUntouched pins renew's no-op branch: a
// binding that already outlives the term about to be advertised is not
// rewritten, so a client hammering REQUEST does not hammer sqlite. A fake
// "now" keeps this deterministic; driven off the wall clock, whether the
// following renewal call lands in this branch or the update one depends on
// which way the previous expiry happened to round.
func TestRenewLeavesFullTermBindingUntouched(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	p := &pluginState{leasedb: db, LeaseTime: testLeaseTime}
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	rec := &Record{expires: now.Add(2 * testLeaseTime).Unix(), hostname: "old-name"}

	p.renew(rec, "new-name", now)
	assert.Equal(t, "old-name", rec.hostname, "a binding that already outlives the new term must not be rewritten")
	assert.Equal(t, now.Add(2*testLeaseTime).Unix(), rec.expires)
}

// TestReleaseLeaseFailureBranches covers releaseLease's two error returns.
// Storage goes first on purpose: a binding that can't be forgotten on disk
// must stay tracked, since a restart would reload the row and hand the
// address to a second client. The allocator is asked to free regardless of
// whether it succeeds, since the row is already gone by then.
func TestReleaseLeaseFailureBranches(t *testing.T) {
	t.Run("storage delete fails", func(t *testing.T) {
		db, err := loadDB(t.Context(), ":memory:")
		require.NoError(t, err)
		require.NoError(t, db.Close())

		rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
		p := &pluginState{leasedb: db, Records6: map[string]*Record{rec.key(): rec}, allocator: &mockAllocator{}}

		err = p.releaseLease(rec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "removing the binding from storage")
		_, stillTracked := p.Records6[rec.key()]
		assert.True(t, stillTracked, "an unforgettable binding must stay tracked")
	})

	t.Run("allocator free fails", func(t *testing.T) {
		db, err := loadDB(t.Context(), ":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		rec := &Record{DUID: duidB, IAID: iaidX, IP: net.ParseIP("2001:db8:1::101")}
		mockAlloc := &mockFailingAllocator{}
		mockAlloc.On("Free", mock.Anything).Return(errors.New("simulated double free"))
		p := &pluginState{leasedb: db, Records6: map[string]*Record{rec.key(): rec}, allocator: mockAlloc}

		err = p.releaseLease(rec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "freeing")
		_, stillTracked := p.Records6[rec.key()]
		assert.False(t, stillTracked, "the row is already gone, so the record must not stay tracked")
		mockAlloc.AssertExpectations(t)
	})
}

// TestReleaseIANAStorageFailureReturnsUnspecFail covers releaseIANA's error
// branch: a release that names a real binding but can't be persisted answers
// with StatusUnspecFail instead of Success.
func TestReleaseIANAStorageFailureReturnsUnspecFail(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
	p := &pluginState{leasedb: db, Records6: map[string]*Record{rec.key(): rec}, allocator: &mockAllocator{}}

	ia := &dhcpv6.OptIANA{IaId: iaidX}
	ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: rec.IP})

	answer := p.releaseIANA(duidA, ia)
	require.NotNil(t, answer)
	status := answer.Options.Status()
	require.NotNil(t, status)
	assert.Equal(t, dhcpIana.StatusUnspecFail, status.StatusCode)
}

// TestDeclineIANAStorageFailureReturnsUnspecFail mirrors
// TestReleaseIANAStorageFailureReturnsUnspecFail for the decline path.
func TestDeclineIANAStorageFailureReturnsUnspecFail(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
	p := &pluginState{
		leasedb:          db,
		Records6:         map[string]*Record{rec.key(): rec},
		declined:         make(map[string]time.Time),
		declineProbation: defaultDeclineProbation,
		declineMax:       1,
	}

	ia := &dhcpv6.OptIANA{IaId: iaidX}
	ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: rec.IP})

	answer := p.declineIANA(duidA, ia, time.Now())
	require.NotNil(t, answer)
	status := answer.Options.Status()
	require.NotNil(t, status)
	assert.Equal(t, dhcpIana.StatusUnspecFail, status.StatusCode)
}

// TestQuarantineFreeIPAddressFailure covers quarantine's own storage error,
// reached only when probation and the quarantine bound are both non-zero.
func TestQuarantineFreeIPAddressFailure(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
	p := &pluginState{
		leasedb:          db,
		Records6:         map[string]*Record{rec.key(): rec},
		declined:         make(map[string]time.Time),
		declineProbation: defaultDeclineProbation,
		declineMax:       1,
	}

	err = p.quarantine(rec, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "removing the declined binding from storage")
}

// TestFreeDeclinedDropsEntryEvenOnAllocatorError pins the documented
// contract: keeping a declined entry the allocator refuses to free would
// wedge the quarantine at its bound forever.
func TestFreeDeclinedDropsEntryEvenOnAllocatorError(t *testing.T) {
	const ip = "2001:db8:1::50"
	mockAlloc := &mockFailingAllocator{}
	mockAlloc.On("Free", mock.Anything).Return(errors.New("double free"))

	p := &pluginState{allocator: mockAlloc, declined: map[string]time.Time{ip: time.Now()}}
	p.freeDeclined(ip)

	assert.Empty(t, p.declined)
	mockAlloc.AssertExpectations(t)
}

// TestSweepExpiredSkipsUndeletableRecordButReclaimsOthers covers both of
// sweepExpired's outcomes in one pass: a record whose row a trigger refuses
// to delete stays tracked, while a normal lapsed record is reclaimed.
func TestSweepExpiredSkipsUndeletableRecordButReclaimsOthers(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	alloc, err := bitmap.NewIPv6Allocator(net.ParseIP("2001:db8:1::100"), net.ParseIP("2001:db8:1::102"))
	require.NoError(t, err)

	p := &pluginState{leasedb: db, Records6: make(map[string]*Record), allocator: alloc, LeaseTime: testLeaseTime}
	now := time.Now()

	stuck := &Record{DUID: duidA, IAID: [4]byte{0, 0, 0, 1}, IP: net.ParseIP("2001:db8:1::100"), expires: now.Add(-time.Hour).Unix()}
	reclaimable := &Record{DUID: duidB, IAID: [4]byte{0, 0, 0, 2}, IP: net.ParseIP("2001:db8:1::101"), expires: now.Add(-time.Hour).Unix()}

	for _, rec := range []*Record{stuck, reclaimable} {
		_, err := alloc.Allocate(net.IPNet{IP: rec.IP})
		require.NoError(t, err)
		require.NoError(t, p.saveIPAddress(rec))
		p.Records6[rec.key()] = rec
	}

	// A trigger that refuses to delete one record's row, standing in for any
	// storage failure that hits a single row mid-sweep.
	_, err = db.Exec(fmt.Sprintf(`
		CREATE TRIGGER prevent_delete
		BEFORE DELETE ON leases6
		WHEN OLD.iaid = %d
		BEGIN
			SELECT RAISE(ABORT, 'deletion blocked');
		END
	`, iaidValue(stuck.IAID)))
	require.NoError(t, err)

	freed := p.sweepExpired(now)
	assert.Equal(t, 1, freed, "the sweep continues past the record it cannot delete")

	_, stillTracked := p.Records6[stuck.key()]
	assert.True(t, stillTracked, "the undeletable record stays tracked so its address is not handed out twice")
	_, tracked := p.Records6[reclaimable.key()]
	assert.False(t, tracked)
}

// TestSweepDeclinedFreesOnlyEndedProbation covers both branches of
// sweepDeclined: an address whose probation has run out is freed, one that
// hasn't is left parked.
func TestSweepDeclinedFreesOnlyEndedProbation(t *testing.T) {
	const endedIP, activeIP = "2001:db8:1::10", "2001:db8:1::11"
	now := time.Now()

	mockAlloc := &mockAllocator{}
	mockAlloc.On("Free", net.IPNet{IP: net.ParseIP(endedIP)}).Return(nil)

	p := &pluginState{
		allocator: mockAlloc,
		declined: map[string]time.Time{
			endedIP:  now.Add(-time.Second),
			activeIP: now.Add(time.Hour),
		},
	}

	freed := p.sweepDeclined(now)
	assert.Equal(t, 1, freed)
	_, stillParked := p.declined[activeIP]
	assert.True(t, stillParked)
	_, gone := p.declined[endedIP]
	assert.False(t, gone)
	mockAlloc.AssertNotCalled(t, "Free", net.IPNet{IP: net.ParseIP(activeIP)})
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

// TestSweeperReclaimsInBackground drives the real ticker: without any client
// asking for an address, an expired binding must disappear from the map on
// its own.
//
// The whole instance is built inside the bubble, ticker and stop channel
// included, which is what lets the sweep happen on bubble time instead of
// being waited out on the wall clock.
func TestSweeperReclaimsInBackground(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, clock := newTestPluginState(t, net.ParseIP("2001:db8:1::100"), net.ParseIP("2001:db8:1::100"))

		rec := p.allocateLease(leaseKey(duidA, iaidX), duidA, iaidX, net.IPNet{}, "", clock.Now())
		require.NotNil(t, rec)
		rec.expires = clock.Now().Add(-time.Second).Unix()

		p.startSweeper(time.Minute)
		defer p.stopSweeper()

		// One tick, then wait for the sweep it starts to finish.
		time.Sleep(time.Minute + time.Second)
		synctest.Wait()

		p.Lock()
		defer p.Unlock()
		assert.Empty(t, p.Records6, "the background sweeper must reclaim the expired binding")
	})
}

// TestStopSweeperHaltsTheLoopImmediately covers the select's stop branch: a
// sweeper stopped before its ticker has any chance to fire must still exit.
func TestStopSweeperHaltsTheLoopImmediately(t *testing.T) {
	p, _ := newTestPluginState(t, net.ParseIP("2001:db8:1::100"), net.ParseIP("2001:db8:1::100"))
	p.startSweeper(time.Hour)
	p.stopSweeper()

	select {
	case <-p.done:
	default:
		t.Fatal("stopSweeper must wait for the loop to exit")
	}
}

// TestRestoreRefusesToSwapRunningDB covers restore's own failure branch: a
// pluginState whose leasedb is already set must not silently swap it out.
func TestRestoreRefusesToSwapRunningDB(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	p := &pluginState{leasedb: db}
	err = p.restore(t.Context(), "irrelevant.db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not setup lease storage")
	assert.Contains(t, err.Error(), "cannot swap out a lease database while running")
}

// TestNewPluginStateAllocatorCreationError substitutes the newIPv6Allocator
// seam to simulate bitmap.NewIPv6Allocator failing. newPluginState's own
// pool-bounds validation already guarantees the real allocator constructor
// can't fail, so this is otherwise unreachable through the public API.
func TestNewPluginStateAllocatorCreationError(t *testing.T) {
	orig := newIPv6Allocator
	t.Cleanup(func() { newIPv6Allocator = orig })
	newIPv6Allocator = func(net.IP, net.IP) (*bitmap.IPv6Allocator, error) {
		return nil, errors.New("simulated allocator creation failure")
	}

	dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
	_, err := newPluginState(dbPath, poolFirst, poolLast, "1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not create an allocator")
}

// TestSetup6ReturnsAWorkingHandler is the happy path setup6 itself adds on
// top of newPluginState: a working handler once the sweeper has started.
func TestSetup6ReturnsAWorkingHandler(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
	h, err := setup6(dbPath, poolFirst, poolLast, "1h")
	require.NoError(t, err)
	assert.NotNil(t, h)
}

// TestLoadDBOpenErrorSeam substitutes the sqlOpen seam, since the real
// sqlite driver defers connecting until first use and sql.Open itself never
// actually fails for it.
func TestLoadDBOpenErrorSeam(t *testing.T) {
	orig := sqlOpen
	t.Cleanup(func() { sqlOpen = orig })
	sqlOpen = func(string, string) (*sql.DB, error) {
		return nil, errors.New("simulated open failure")
	}

	_, err := loadDB(t.Context(), filepath.Join(t.TempDir(), "leases6.sqlite3"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

// TestLoadDBTableCreationFailure covers the other way opening a lease
// database can fail: the path exists but isn't a usable sqlite file. A
// directory can never be opened as one.
func TestLoadDBTableCreationFailure(t *testing.T) {
	_, err := loadDB(t.Context(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "table creation failed")
}

func TestLoadRecordsQueryError(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = loadRecords(t.Context(), db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to query leases database")
}

// TestLoadRecordsScanFailure seeds a row with an iaid value sqlite can't
// coerce to an integer, which loadRecords can only ever see by scanning
// straight into a mismatched type: a row written through saveIPAddress
// could never carry one.
func TestLoadRecordsScanFailure(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)

	_, err = db.Exec(
		"insert into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)",
		[]byte{0xaa}, "not-a-number", "2001:db8:1::1", 1, "host",
	)
	require.NoError(t, err)

	_, err = loadRecords(t.Context(), db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to scan row")
}

// errRowsDriver is a minimal database/sql/driver implementation whose Rows
// always fail iteration with a non-io.EOF error, exercising loadRecords'
// rows.Err() branch deterministically. A real sqlite query result is
// materialized up front, so that branch can't be triggered through the
// sqlite driver itself.
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

func (r *errRows) Columns() []string { return []string{"duid", "iaid", "ip", "expiry", "hostname"} }
func (r *errRows) Close() error      { return nil }
func (r *errRows) Next([]driver.Value) error {
	return errors.New("simulated row iteration failure")
}

func TestLoadRecordsRowsIterationError(t *testing.T) {
	const driverName = "range6_errrows_test"
	sql.Register(driverName, errRowsDriver{})

	db, err := sql.Open(driverName, "irrelevant")
	require.NoError(t, err)

	_, err = loadRecords(t.Context(), db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed lease database row scanning")
	assert.Contains(t, err.Error(), "simulated row iteration failure")
}

// TestRestoreFailsWhenReallocationExhaustsThePool covers restore's other
// re-allocation failure: two stored rows naming the same address in a
// single-address pool. The first reclaims it, and the second finds the
// allocator with nothing left to give back at all, rather than merely
// getting handed a different address (which is what
// TestSetupRejectsUnusableStoredRows's "address outside the pool" case
// covers).
func TestRestoreFailsWhenReallocationExhaustsThePool(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "leases6.sqlite3")
	db, err := loadDB(t.Context(), dbPath)
	require.NoError(t, err)

	const sameIP = "2001:db8:1::100"
	_, err = db.Exec("insert into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)",
		[]byte{0x01}, 1, sameIP, 0, "")
	require.NoError(t, err)
	_, err = db.Exec("insert into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)",
		[]byte{0x02}, 1, sameIP, 0, "")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = newPluginState(dbPath, sameIP, sameIP, "1h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to re-allocate leased ip")
}

func TestSaveIPAddressExecFailure(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	p := &pluginState{leasedb: db}
	err = p.saveIPAddress(&Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not store the binding")
}

func TestFreeIPAddressExecFailure(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	p := &pluginState{leasedb: db}
	err = p.freeIPAddress(&Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not remove the binding")
}

func TestRegisterBackingDBDoubleRegistration(t *testing.T) {
	p := &pluginState{}
	require.NoError(t, p.registerBackingDB(t.Context(), ":memory:"))
	t.Cleanup(func() { _ = p.leasedb.Close() })

	err := p.registerBackingDB(t.Context(), ":memory:")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot swap out a lease database")
}

// TestRecordFromRow covers every one of recordFromRow's rejections, plus the
// happy path, as the cheapest way to document what a stored row must look
// like.
func TestRecordFromRow(t *testing.T) {
	validDUID := []byte{0xaa, 0xbb}

	for _, tc := range []struct {
		name       string
		duid       []byte
		iaid       int64
		ip         string
		wantErrSub string
	}{
		{"empty DUID", []byte{}, 1, "2001:db8:1::1", "stored client DUID is"},
		{"DUID over the limit", make([]byte, maxDUIDLen+1), 1, "2001:db8:1::1", "stored client DUID is"},
		{"negative IAID", validDUID, -1, "2001:db8:1::1", "outside the 32-bit range"},
		{"IAID past 32 bits", validDUID, int64(math.MaxUint32) + 1, "2001:db8:1::1", "outside the 32-bit range"},
		{"malformed IP", validDUID, 1, "not-an-ip", "expected an IPv6 address"},
		{"IPv4 address", validDUID, 1, "10.0.0.1", "expected an IPv6 address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := recordFromRow(tc.duid, tc.iaid, tc.ip, 0, "host")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}

	t.Run("happy path", func(t *testing.T) {
		rec, err := recordFromRow(validDUID, 1, "2001:db8:1::1", 42, "host")
		require.NoError(t, err)
		assert.Equal(t, validDUID, rec.DUID)
		assert.Equal(t, [4]byte{0, 0, 0, 1}, rec.IAID)
		assert.Equal(t, net.ParseIP("2001:db8:1::1").To16(), rec.IP)
		assert.Equal(t, int64(42), rec.expires)
		assert.Equal(t, "host", rec.hostname)
	})
}

// TestLogThrottleReady drives a throttle through a full cycle: the first call
// always gets through, calls inside the window are suppressed and counted,
// and the first call past the window gets through again carrying how many
// were held back. It runs the cycle at two different window lengths, since
// the window is whatever the caller chooses and not a fixed constant of the
// throttle itself.
func TestLogThrottleReady(t *testing.T) {
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	t.Run("a one-minute window", func(t *testing.T) {
		var throttle logThrottle
		const window = time.Minute

		skipped, ok := throttle.ready(start, window)
		assert.True(t, ok, "the first call always gets through")
		assert.Zero(t, skipped)

		skipped, ok = throttle.ready(start.Add(30*time.Second), window)
		assert.False(t, ok, "a call inside the window is suppressed")
		assert.Zero(t, skipped, "a suppressed call reports nothing yet, the count comes back on the next one that gets through")

		skipped, ok = throttle.ready(start.Add(45*time.Second), window)
		assert.False(t, ok, "a second call inside the window keeps counting")
		assert.Zero(t, skipped)

		skipped, ok = throttle.ready(start.Add(61*time.Second), window)
		assert.True(t, ok, "a call past the window gets through again")
		assert.Equal(t, uint64(2), skipped, "carrying how many were held back")
	})

	t.Run("a 200-millisecond window", func(t *testing.T) {
		var throttle logThrottle
		const window = 200 * time.Millisecond

		skipped, ok := throttle.ready(start, window)
		assert.True(t, ok)
		assert.Zero(t, skipped)

		skipped, ok = throttle.ready(start.Add(100*time.Millisecond), window)
		assert.False(t, ok)
		assert.Zero(t, skipped)

		skipped, ok = throttle.ready(start.Add(300*time.Millisecond), window)
		assert.True(t, ok)
		assert.Equal(t, uint64(1), skipped)
	})
}

// TestAtLeaseLimit covers the three shapes of the bound: turned off, exactly
// full, and still under it.
func TestAtLeaseLimit(t *testing.T) {
	now := time.Now()
	// The bindings have to be live: one that has lapsed is reclaimed rather
	// than counted against the bound, which is the case after this table.
	records := func(n int) map[string]*Record {
		recs := make(map[string]*Record, n)
		for i := range n {
			recs[fmt.Sprintf("rec-%d", i)] = &Record{expires: now.Add(time.Hour).Unix()}
		}
		return recs
	}

	for _, tc := range []struct {
		name      string
		maxLeases int
		records   int
		want      bool
	}{
		{"a bound of zero is off, whatever the map holds", 0, 5, false},
		{"exactly at the bound is full", 3, 3, true},
		{"below the bound is not full", 3, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &pluginState{maxLeases: tc.maxLeases, Records6: records(tc.records), declined: map[string]time.Time{}}
			assert.Equal(t, tc.want, p.atLeaseLimit(now))
		})
	}

	// A full table of bindings nobody holds any more must not turn a client
	// away: the background sweeper would return them, but only at the next
	// tick, and the client is asking now.
	t.Run("a lapsed binding is reclaimed rather than counted against the bound", func(t *testing.T) {
		p, clock := newTestPluginState(t, net.ParseIP(poolFirst), net.ParseIP("2001:db8:1::101"))
		p.maxLeases = 1
		require.NotNil(t, p.allocateLease(leaseKey(duidA, iaidX), duidA, iaidX, net.IPNet{}, "", clock.Now()))

		clock.Advance(testLeaseTime + time.Second)
		assert.False(t, p.atLeaseLimit(clock.Now()))
		assert.Empty(t, p.Records6, "the lapsed binding went back to the pool")
	})
}

// TestAllocateLeaseRefusesAtLeaseLimit covers allocateLease's own refusal
// branch: once the table already holds max-leases bindings, a new DUID and
// IAID pair gets nothing, the table does not grow, and the allocator is never
// even asked.
func TestAllocateLeaseRefusesAtLeaseLimit(t *testing.T) {
	existing := &Record{
		DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100"),
		// Live, so the bound is what refuses the next client rather than
		// the reclaim atLeaseLimit runs first.
		expires: time.Now().Add(time.Hour).Unix(),
	}
	mockAlloc := &mockAllocator{}
	p := &pluginState{
		maxLeases: 1,
		Records6:  map[string]*Record{existing.key(): existing},
		declined:  map[string]time.Time{},
		allocator: mockAlloc,
	}

	key := leaseKey(duidB, iaidX)
	rec := p.allocateLease(key, duidB, iaidX, net.IPNet{}, "new-client", time.Now())

	assert.Nil(t, rec)
	assert.Len(t, p.Records6, 1, "the table must not grow past the bound")
	_, added := p.Records6[key]
	assert.False(t, added)
	mockAlloc.AssertNotCalled(t, "Allocate", mock.Anything)
}

// TestAllocateLeaseSaveFailureAndFreeFailureAreBothLogged covers the doubly
// unlucky path inside allocateLease: the binding could not be persisted, and
// returning the freshly allocated address to the pool then fails too. Both
// failures are logged and the caller still gets nothing.
func TestAllocateLeaseSaveFailureAndFreeFailureAreBothLogged(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close()) // force saveIPAddress to fail

	mockAlloc := &mockFailingAllocator{}
	mockAlloc.On("Allocate", mock.Anything).Return(net.IPNet{IP: net.ParseIP(poolFirst)}, nil)
	mockAlloc.On("Free", mock.Anything).Return(errors.New("double free"))

	p := &pluginState{leasedb: db, Records6: make(map[string]*Record), allocator: mockAlloc, LeaseTime: testLeaseTime}
	key := leaseKey(duidA, iaidX)

	assert.Nil(t, p.allocateLease(key, duidA, iaidX, net.IPNet{}, "client-a", time.Now()))
	assert.Empty(t, p.Records6)
	mockAlloc.AssertExpectations(t)
}

// TestWriteLogsNotFoundWithoutTreatingItAsAFailure covers write's ErrNotFound
// case directly: a delete that matched nothing is not a failure, so the
// writer logs it at debug and moves on without retrying.
func TestWriteLogsNotFoundWithoutTreatingItAsAFailure(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	p := &pluginState{leasedb: db}
	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
	w := bindingWrite{
		op:    "remove",
		duid:  rec.DUID,
		iaid:  rec.IAID,
		ip:    rec.IP.String(),
		query: `delete from leases6 where duid = ? and iaid = ? and ip = ?`,
		args:  []any{rec.DUID, iaidValue(rec.IAID), rec.IP.String()},
	}

	p.write(w) // the row was never there; this must not panic or retry
}

// TestParseOptions covers parseOptions and the parsers it dispatches to for
// max-leases, which nothing else in this file reaches directly.
func TestParseOptions(t *testing.T) {
	for _, tc := range []struct {
		name          string
		extra         []string
		wantErrSub    string
		wantMaxLeases int
	}{
		{
			name:          "no extra arguments keeps the default",
			wantMaxLeases: defaultMaxLeases,
		},
		{
			name:          "max-leases is accepted",
			extra:         []string{"max-leases:4096"},
			wantMaxLeases: 4096,
		},
		{
			name:          "max-leases of zero turns the bound off",
			extra:         []string{"max-leases:0"},
			wantMaxLeases: 0,
		},
		{
			name:       "a negative max-leases is rejected",
			extra:      []string{"max-leases:-1"},
			wantErrSub: "cannot be negative",
		},
		{
			name:       "a non-numeric max-leases is rejected",
			extra:      []string{"max-leases:lots"},
			wantErrSub: "invalid lease maximum",
		},
		{
			name:       "max-leases given twice is rejected",
			extra:      []string{"max-leases:10", "max-leases:20"},
			wantErrSub: "max-leases given more than once",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseOptions(testLeaseTime, 100, tc.extra)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMaxLeases, opts.maxLeases)
		})
	}
}

// TestBindingExpiryPast2038 is the regression test for a 32-bit build
// truncating the expiry: a binding expiring well past 2038 must round-trip
// through storage unchanged and must not read as expired before it actually
// is.
func TestBindingExpiryPast2038(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	future := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100"), expires: future}

	p := &pluginState{leasedb: db}
	require.NoError(t, p.saveIPAddress(rec))

	records, err := loadRecords(t.Context(), db)
	require.NoError(t, err)
	got, ok := records[rec.key()]
	require.True(t, ok)
	assert.Equal(t, future, got.expires)

	clockIn2099 := time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
	assert.False(t, got.expired(clockIn2099), "a binding expiring in 2100 must not read as expired in 2099")
}

// TestEnqueueQueueFull covers enqueue's queue-full branch: the plugin lock is
// held by the caller, so a slow writer must be reported back rather than
// waited on.
func TestEnqueueQueueFull(t *testing.T) {
	p := &pluginState{writes: make(chan bindingWrite, 1)}
	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}

	require.NoError(t, p.saveIPAddress(rec), "the first write fills the one-deep queue")

	err := p.saveIPAddress(rec)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWriteQueueFull)

	err = p.freeIPAddress(rec)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWriteQueueFull)
}

// TestApplyWriteNotFound covers applyWrite's own ErrNotFound branch directly:
// enqueue's inline path deliberately swallows that sentinel, so the sentinel
// itself has to be pinned one level down.
func TestApplyWriteNotFound(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	p := &pluginState{leasedb: db}
	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
	w := bindingWrite{
		op:    "remove",
		duid:  rec.DUID,
		iaid:  rec.IAID,
		ip:    rec.IP.String(),
		query: `delete from leases6 where duid = ? and iaid = ? and ip = ?`,
		args:  []any{rec.DUID, iaidValue(rec.IAID), rec.IP.String()},
	}

	err = p.applyWrite(w)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestWriterFailureIsLoggedWithoutRetrying covers write's non-busy failure
// path: a closed database fails every attempt with something other than
// ErrBusy, so the writer logs it once and moves on instead of retrying.
func TestWriterFailureIsLoggedWithoutRetrying(t *testing.T) {
	db, err := loadDB(t.Context(), ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	p := &pluginState{leasedb: db}
	p.startWriter()

	rec := &Record{DUID: duidA, IAID: iaidX, IP: net.ParseIP("2001:db8:1::100")}
	require.NoError(t, p.saveIPAddress(rec))

	p.stopWriter()
}

// TestWriterRetriesOnBusyThenGivesUp holds the write lock on a file through a
// second connection so the writer's own write gets a real SQLITE_BUSY, and
// checks it retries busyRetries times before giving up rather than hanging.
func TestWriterRetriesOnBusyThenGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases6.db")
	db1, err := loadDB(t.Context(), path) // holds the write lock
	require.NoError(t, err)
	db2, err := loadDB(t.Context(), path) // what the writer uses, and finds locked
	require.NoError(t, err)

	tx, err := db1.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(),
		"insert into leases6(duid, iaid, ip, expiry, hostname) values (?, ?, ?, ?, ?)",
		[]byte{0x01}, 1, "2001:db8:1::1", 0, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = tx.Rollback()
		_ = db1.Close()
		_ = db2.Close()
	})

	p := &pluginState{leasedb: db2}
	p.startWriter()

	rec := &Record{DUID: duidB, IAID: iaidX, IP: net.ParseIP("2001:db8:1::101")}
	require.NoError(t, p.saveIPAddress(rec))

	p.stopWriter()
}
