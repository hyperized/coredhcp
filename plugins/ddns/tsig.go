// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ddns

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // See the algorithms map for why SHA-1 is here.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Kept separate from the plain transport errors so a bad key reads
// differently in the log from an unreachable server.
var (
	// ErrUnknownAlgorithm is an algo: this plugin does not implement.
	ErrUnknownAlgorithm = errors.New("ddns: unknown TSIG algorithm")

	// ErrNoTSIG is a response with no TSIG record: for a signed request, that
	// means the server never authenticated and nothing in it can be trusted.
	ErrNoTSIG = errors.New("ddns: response is not signed")

	// ErrTSIGPlacement is a TSIG record not where RFC 8945 puts it, or with a
	// compressed or rewritten owner name; either way the signed bytes are lost.
	ErrTSIGPlacement = errors.New("ddns: TSIG record is not the last record of the response")

	// ErrTSIGKey is a response signed with a different key or a different
	// algorithm from the one the request used.
	ErrTSIGKey = errors.New("ddns: response is signed with the wrong key")

	// ErrTSIGError is a response whose TSIG carries its own error (BADKEY,
	// BADSIG, BADTIME); BADTIME means the two clocks differ by more than the fudge.
	ErrTSIGError = errors.New("ddns: server rejected the signature")

	// ErrBadMAC is a response whose MAC does not verify; nothing in it,
	// including the RCODE, can be believed.
	ErrBadMAC = errors.New("ddns: response MAC does not verify")

	// ErrShortRDATA is a TSIG RDATA that ends in the middle of a field.
	ErrShortRDATA = errors.New("ddns: truncated TSIG record")
)

const (
	// dnsmessage has no constant or body type for TSIG, so it is handled
	// here as an opaque resource record.
	typeTSIG = dnsmessage.Type(250)

	// 300 seconds: what RFC 8945 suggests and what nsupdate sends.
	tsigFudge = 300

	// Bytes between a record's owner name and its RDATA: type, class, TTL, RDLENGTH.
	tsigRRFixedLen = 10

	// Fixed DNS header size, and the byte offset of its ARCOUNT field.
	headerLen  = 12
	arcountOff = 10
)

// HMAC-SHA1 stays for RFC 8945 compatibility and old key material; as a
// keyed MAC it isn't exposed to SHA-1's collision weakness.
var algorithms = map[string]func() hash.Hash{
	"hmac-sha1":   sha1.New,
	"hmac-sha256": sha256.New,
	"hmac-sha512": sha512.New,
}

func algorithmNames() []string {
	names := make([]string, 0, len(algorithms))
	for name := range algorithms {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Immutable once built, safe to share across goroutines. No method prints
// the secret, and returned errors name the key, never its value.
type tsigKey struct {
	name     string // presentation form, lowercase, trailing dot
	nameWire []byte
	algo     string // presentation form, lowercase, trailing dot
	algoWire []byte
	newHash  func() hash.Hash
	secret   []byte
}

func newTSIGKey(name, algo string, secret []byte) (tsigKey, error) {
	newHash, ok := algorithms[algo]
	if !ok {
		return tsigKey{}, fmt.Errorf("%w %q, want one of %v", ErrUnknownAlgorithm, algo, algorithmNames())
	}
	k := tsigKey{name: dot(name), algo: dot(algo), algoWire: packLabel(algo), newHash: newHash, secret: secret}
	var err error
	if k.nameWire, err = packName(k.name); err != nil {
		return tsigKey{}, fmt.Errorf("key name %q: %w", name, err)
	}
	return k, nil
}

// No error return: the only inputs are algorithms map keys, fixed strings
// well under the label limit.
func packLabel(label string) []byte {
	out := make([]byte, 0, len(label)+2)
	//nolint:gosec // callers only pass algorithms map keys, held to packName's output by the sibling test.
	out = append(out, byte(len(label)))
	out = append(out, label...)
	return append(out, 0)
}

func dot(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}

// The returned MAC lets the caller verify the answer (RFC 8945 section 5.4).
// signedAt is compared against the server's own clock; drift beyond the
// fudge gets a named BADTIME failure instead of a silent one.
func (k tsigKey) sign(msg []byte, signedAt time.Time, origID uint16) ([]byte, []byte) {
	ts := unixSeconds(signedAt)
	mac := k.digest(msg, ts, nil)
	out := k.appendRR(msg, ts, mac, origID)
	binary.BigEndian.PutUint16(out[arcountOff:], binary.BigEndian.Uint16(out[arcountOff:])+1)
	return out, mac
}

// A clock not yet set reads as the epoch, not a wraparound into the far
// future, which a naive int64-to-uint64 conversion would produce.
func unixSeconds(signedAt time.Time) uint64 {
	s := signedAt.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// msg must exclude the TSIG record and carry the pre-append ARCOUNT (RFC 8945
// section 4.3.3). requestMAC, when present, ties a response to its request.
func (k tsigKey) digest(msg []byte, timeSigned uint64, requestMAC []byte) []byte {
	h := hmac.New(k.newHash, k.secret)
	if len(requestMAC) > 0 {
		var size [2]byte
		//nolint:gosec // A MAC is at most 64 octets: it comes out of one of
		// the hashes in the algorithms map.
		binary.BigEndian.PutUint16(size[:], uint16(len(requestMAC)))
		write(h, size[:])
		write(h, requestMAC)
	}
	write(h, msg)
	write(h, k.variables(timeSigned))
	return h.Sum(nil)
}

// hash.Hash never returns a write error; the assignment just makes that explicit.
func write(h hash.Hash, b []byte) {
	_, _ = h.Write(b)
}

// TSIG variables per RFC 8945 section 4.3.3. Error and Other Data are always
// zero: only a NOERROR reply is accepted, so BADTIME's use of Other Data never applies.
func (k tsigKey) variables(timeSigned uint64) []byte {
	buf := make([]byte, 0, len(k.nameWire)+len(k.algoWire)+18)
	buf = append(buf, k.nameWire...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(dnsmessage.ClassANY))
	buf = binary.BigEndian.AppendUint32(buf, 0) // TTL
	buf = append(buf, k.algoWire...)
	buf = appendUint48(buf, timeSigned)
	buf = binary.BigEndian.AppendUint16(buf, tsigFudge)
	buf = binary.BigEndian.AppendUint16(buf, 0) // Error: NOERROR
	buf = binary.BigEndian.AppendUint16(buf, 0) // Other Len
	return buf
}

// Caller is responsible for bumping ARCOUNT.
func (k tsigKey) appendRR(msg []byte, timeSigned uint64, mac []byte, origID uint16) []byte {
	rdata := make([]byte, 0, len(k.algoWire)+len(mac)+18)
	rdata = append(rdata, k.algoWire...)
	rdata = appendUint48(rdata, timeSigned)
	rdata = binary.BigEndian.AppendUint16(rdata, tsigFudge)
	//nolint:gosec // See digest: a MAC is at most 64 octets.
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(mac)))
	rdata = append(rdata, mac...)
	rdata = binary.BigEndian.AppendUint16(rdata, origID)
	rdata = binary.BigEndian.AppendUint16(rdata, 0) // Error
	rdata = binary.BigEndian.AppendUint16(rdata, 0) // Other Len

	msg = append(msg, k.nameWire...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(typeTSIG))
	msg = binary.BigEndian.AppendUint16(msg, uint16(dnsmessage.ClassANY))
	msg = binary.BigEndian.AppendUint32(msg, 0) // TTL
	//nolint:gosec // RDATA is a name, a MAC and seven fixed width fields: a few hundred octets at most.
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	return append(msg, rdata...)
}

// RFC 8945 carries Time Signed as 48 bits.
func appendUint48(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[2:]...)
}

type tsigRecord struct {
	name       string
	algo       string
	timeSigned uint64
	fudge      uint16
	mac        []byte
	origID     uint16
	rcode      uint16
	other      []byte
	rdataLen   int
}

// RFC 8945 section 5.2: TSIG is the last record of the additional section,
// so the digest covers everything in front of it.
func findTSIG(msg []byte) (tsigRecord, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return tsigRecord{}, fmt.Errorf("parsing the response: %w", err)
	}
	if err := skipToAdditionals(&p); err != nil {
		return tsigRecord{}, fmt.Errorf("parsing the response: %w", err)
	}
	hdr, rdata, err := lastAdditional(&p)
	if err != nil {
		return tsigRecord{}, err
	}
	if hdr.Type != typeTSIG {
		return tsigRecord{}, fmt.Errorf("%w: the last record is a %s", ErrNoTSIG, hdr.Type)
	}
	rec, err := parseTSIGRDATA(rdata)
	if err != nil {
		return tsigRecord{}, err
	}
	rec.name = dot(hdr.Name.String())
	return rec, nil
}

// An UPDATE response echoes the zone, prerequisite and update sections
// before its additional section.
func skipToAdditionals(p *dnsmessage.Parser) error {
	if err := p.SkipAllQuestions(); err != nil {
		return err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return err
	}
	return p.SkipAllAuthorities()
}

func lastAdditional(p *dnsmessage.Parser) (dnsmessage.ResourceHeader, []byte, error) {
	var (
		hdr   dnsmessage.ResourceHeader
		rdata []byte
		found bool
	)
	for {
		next, err := p.AdditionalHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return hdr, nil, fmt.Errorf("parsing the response: %w", err)
		}
		body, err := p.UnknownResource()
		if err != nil {
			return hdr, nil, fmt.Errorf("parsing the response: %w", err)
		}
		hdr, rdata, found = next, body.Data, true
	}
	if !found {
		return hdr, nil, fmt.Errorf("%w: the additional section is empty", ErrNoTSIG)
	}
	return hdr, rdata, nil
}

// parseTSIGRDATA reads the RDATA fields of RFC 8945 section 4.2.
func parseTSIGRDATA(rdata []byte) (tsigRecord, error) {
	r := rdataReader{b: rdata}
	rec := tsigRecord{rdataLen: len(rdata)}
	rec.algo = r.name()
	rec.timeSigned = r.uint48()
	rec.fudge = r.uint16()
	macLen := r.uint16()
	rec.mac = r.take(int(macLen))
	rec.origID = r.uint16()
	rec.rcode = r.uint16()
	otherLen := r.uint16()
	rec.other = r.take(int(otherLen))
	if r.err != nil {
		return tsigRecord{}, fmt.Errorf("TSIG record: %w", r.err)
	}
	return rec, nil
}

func (k tsigKey) verify(msg []byte, rec tsigRecord, requestMAC []byte) error {
	if rec.name != k.name {
		return fmt.Errorf("%w: signed with %s, expected %s", ErrTSIGKey, rec.name, k.name)
	}
	if rec.algo != k.algo {
		return fmt.Errorf("%w: signed with %s, expected %s", ErrTSIGKey, rec.algo, k.algo)
	}
	// Checked before the MAC: RFC 8945 has a BADKEY/BADSIG reply carry a
	// zero-length MAC, so there is nothing to verify there.
	if rec.rcode != 0 {
		return fmt.Errorf("%w: %s", ErrTSIGError, tsigErrorName(rec.rcode))
	}
	unsigned, err := k.stripTSIG(msg, rec.rdataLen)
	if err != nil {
		return err
	}
	if !hmac.Equal(k.digest(unsigned, rec.timeSigned, requestMAC), rec.mac) {
		return ErrBadMAC
	}
	return nil
}

// RFC 8945 section 4.2 forbids compressing the TSIG name; its offset is
// computed from name and RDATA length, so a rewritten name fails here, not later as a bad MAC.
func (k tsigKey) stripTSIG(msg []byte, rdataLen int) ([]byte, error) {
	off := len(msg) - rdataLen - tsigRRFixedLen - len(k.nameWire)
	if off < headerLen || !bytes.EqualFold(msg[off:off+len(k.nameWire)], k.nameWire) {
		return nil, ErrTSIGPlacement
	}
	out := make([]byte, off)
	copy(out, msg[:off])
	binary.BigEndian.PutUint16(out[arcountOff:], binary.BigEndian.Uint16(out[arcountOff:])-1)
	return out, nil
}

// Extended RCODEs a TSIG record can carry (RFC 8945 section 2, IANA registry).
var tsigErrors = map[uint16]string{
	16: "BADSIG",
	17: "BADKEY",
	18: "BADTIME",
	19: "BADMODE",
	20: "BADNAME",
	21: "BADALG",
	22: "BADTRUNC",
}

func tsigErrorName(code uint16) string {
	if name, ok := tsigErrors[code]; ok {
		return name
	}
	return fmt.Sprintf("TSIG error %d", code)
}

// Keeps the first error so a parse reads as a straight sequence of fields,
// not a ladder of length checks.
type rdataReader struct {
	b   []byte
	err error
}

func (r *rdataReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = ErrShortRDATA
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *rdataReader) uint16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *rdataReader) uint48() uint64 {
	b := r.take(6)
	if b == nil {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(b[2:])) | uint64(binary.BigEndian.Uint16(b[:2]))<<32
}

func (r *rdataReader) name() string {
	if r.err != nil {
		return ""
	}
	name, n, err := readName(r.b)
	if err != nil {
		r.err = err
		return ""
	}
	r.b = r.b[n:]
	return name
}
