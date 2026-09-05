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

// Failures on the TSIG side of an exchange. They are separate from the plain
// transport errors so a key that is wrong everywhere reads differently in the
// log from a server that is merely unreachable.
var (
	// ErrUnknownAlgorithm is an algo: this plugin does not implement.
	ErrUnknownAlgorithm = errors.New("ddns: unknown TSIG algorithm")

	// ErrNoTSIG is a response that carries no TSIG record at all, which for
	// an answer to a signed request means the server did not authenticate
	// itself and nothing in the answer can be trusted.
	ErrNoTSIG = errors.New("ddns: response is not signed")

	// ErrTSIGPlacement is a TSIG record that is not where RFC 8945 puts it,
	// or whose owner name was compressed or rewritten. Either way the bytes
	// that were signed cannot be recovered.
	ErrTSIGPlacement = errors.New("ddns: TSIG record is not the last record of the response")

	// ErrTSIGKey is a response signed with a different key or a different
	// algorithm from the one the request used.
	ErrTSIGKey = errors.New("ddns: response is signed with the wrong key")

	// ErrTSIGError is a response whose TSIG carries an error of its own:
	// BADKEY, BADSIG or BADTIME. BADTIME is the common one and means the two
	// clocks are more than the fudge apart.
	ErrTSIGError = errors.New("ddns: server rejected the signature")

	// ErrBadMAC is a response whose MAC does not verify. Nothing in it can
	// be believed, including its RCODE.
	ErrBadMAC = errors.New("ddns: response MAC does not verify")

	// ErrShortRDATA is a TSIG RDATA that ends in the middle of a field.
	ErrShortRDATA = errors.New("ddns: truncated TSIG record")
)

const (
	// typeTSIG is the TSIG record type. dnsmessage has no constant for it
	// and no body type either, which is why TSIG is written and read here as
	// an opaque resource.
	typeTSIG = dnsmessage.Type(250)

	// tsigFudge is the window, in seconds, the server is asked to allow
	// between its clock and the time in the record. 300 is what RFC 8945
	// suggests and what nsupdate sends.
	tsigFudge = 300

	// tsigRRFixedLen is the size of the type, class, TTL and RDLENGTH fields
	// that sit between a record's owner name and its RDATA.
	tsigRRFixedLen = 10

	// headerLen is the size of a DNS message header, and arcountOff is where
	// its ARCOUNT field starts.
	headerLen  = 12
	arcountOff = 10
)

// algorithms maps the name an operator writes in algo: to the hash behind it.
// It is fixed and only ever read.
//
// HMAC-SHA1 is in the list because RFC 8945 names it and because a name
// server that has been running since before SHA-256 was the default may still
// hold keys for it. TSIG uses the hash as a keyed MAC, where the collision
// attacks that retired SHA-1 for signatures do not apply, and nothing here
// reaches it unless a configuration asks for algo:hmac-sha1 by name.
var algorithms = map[string]func() hash.Hash{
	"hmac-sha1":   sha1.New,
	"hmac-sha256": sha256.New,
	"hmac-sha512": sha512.New,
}

// algorithmNames lists the accepted algo: values in a stable order, for error
// messages.
func algorithmNames() []string {
	names := make([]string, 0, len(algorithms))
	for name := range algorithms {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// tsigKey is a TSIG key with everything the signing path needs precomputed.
//
// It is immutable once built and safe to share between goroutines. The secret
// never reaches the log: no method of this type prints it, and the errors it
// returns name the key, never its value.
type tsigKey struct {
	name     string // presentation form, lowercase, trailing dot
	nameWire []byte
	algo     string // presentation form, lowercase, trailing dot
	algoWire []byte
	newHash  func() hash.Hash
	secret   []byte
}

// newTSIGKey builds a key from the configured name, algorithm and secret.
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

// packLabel is packName for a name of exactly one label, which every TSIG
// algorithm name is. It takes no error return because its only inputs are the
// keys of the algorithms map: fixed strings, well under the label limit.
func packLabel(label string) []byte {
	out := make([]byte, 0, len(label)+2)
	//nolint:gosec // The only callers pass a key of the algorithms map, and
	// the test beside this one holds them to what packName would produce.
	out = append(out, byte(len(label)))
	out = append(out, label...)
	return append(out, 0)
}

// dot gives a name its trailing dot if it has none.
func dot(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}

// sign appends a TSIG record to msg and returns the signed message together
// with the MAC, which the caller needs in order to verify the answer
// (RFC 8945 section 5.4).
//
// signedAt is the time that goes on the wire. The server compares it against
// its own clock and answers BADTIME when the two are more than the fudge
// apart, so a host whose clock has drifted gets a named failure instead of a
// silent one.
func (k tsigKey) sign(msg []byte, signedAt time.Time, origID uint16) ([]byte, []byte) {
	ts := unixSeconds(signedAt)
	mac := k.digest(msg, ts, nil)
	out := k.appendRR(msg, ts, mac, origID)
	binary.BigEndian.PutUint16(out[arcountOff:], binary.BigEndian.Uint16(out[arcountOff:])+1)
	return out, mac
}

// unixSeconds is signedAt as the 48-bit unsigned Time Signed field. A clock
// that has not been set yet reads as the epoch rather than as a time in the
// year 8 million, which is what the conversion would otherwise produce.
func unixSeconds(signedAt time.Time) uint64 {
	s := signedAt.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// digest computes the MAC over msg, which has to be the message without the
// TSIG record and with the ARCOUNT it had before the record was added
// (RFC 8945 section 4.3.3).
//
// requestMAC is nil for a request. For a response it is the MAC of the
// request being answered, which is digested first with a two octet length in
// front of it; that is what ties an answer to the question it answers.
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

// write feeds b to h. A hash never reports a write error, which hash.Hash
// documents; the assignment is here so the call reads as deliberate.
func write(h hash.Hash, b []byte) {
	_, _ = h.Write(b)
}

// variables returns the TSIG variables that follow the message in the digest
// (RFC 8945 section 4.3.3): the record's own name, class and TTL, then the
// RDATA fields other than the MAC.
//
// Error and Other Data are always zero. This plugin only signs requests, and
// it only accepts an answer whose TSIG error is NOERROR, so the one case
// where those fields carry something -- a BADTIME reply, which returns the
// server's clock in Other Data -- is refused before the MAC is computed.
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

// appendRR appends the TSIG resource record itself. The caller bumps ARCOUNT.
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
	//nolint:gosec // The RDATA is a name, a MAC and seven fixed width
	// fields: a few hundred octets at the very most.
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	return append(msg, rdata...)
}

// appendUint48 appends the low 48 bits of v, which is how RFC 8945 carries
// Time Signed.
func appendUint48(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[2:]...)
}

// tsigRecord is a TSIG record read back out of a response.
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

// findTSIG returns the TSIG record of msg.
//
// RFC 8945 section 5.2 makes it the last record of the additional section,
// which is what lets the digest be taken over the bytes in front of it.
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

// skipToAdditionals walks the parser past the zone, prerequisite and update
// sections an UPDATE response echoes back.
func skipToAdditionals(p *dnsmessage.Parser) error {
	if err := p.SkipAllQuestions(); err != nil {
		return err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return err
	}
	return p.SkipAllAuthorities()
}

// lastAdditional returns the header and RDATA of the final record of the
// additional section.
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

// verify checks a response's TSIG against this key and the MAC of the request
// it answers.
func (k tsigKey) verify(msg []byte, rec tsigRecord, requestMAC []byte) error {
	if rec.name != k.name {
		return fmt.Errorf("%w: signed with %s, expected %s", ErrTSIGKey, rec.name, k.name)
	}
	if rec.algo != k.algo {
		return fmt.Errorf("%w: signed with %s, expected %s", ErrTSIGKey, rec.algo, k.algo)
	}
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

// stripTSIG returns the message as it was digested: everything in front of
// the TSIG record, with ARCOUNT back down to what it was before the record
// was appended (RFC 8945 section 4.3.3).
//
// The record sits at the end and section 4.2 forbids compressing its owner
// name, so its offset follows from the length of that name and of the RDATA.
// A server that compresses or rewrites the name anyway is refused here, where
// the reason is still visible, rather than three lines later as a MAC that
// does not verify.
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

// tsigErrors names the extended RCODEs a TSIG record can carry (RFC 8945
// section 2 and the IANA registry).
var tsigErrors = map[uint16]string{
	16: "BADSIG",
	17: "BADKEY",
	18: "BADTIME",
	19: "BADMODE",
	20: "BADNAME",
	21: "BADALG",
	22: "BADTRUNC",
}

// tsigErrorName names a TSIG error for the log.
func tsigErrorName(code uint16) string {
	if name, ok := tsigErrors[code]; ok {
		return name
	}
	return fmt.Sprintf("TSIG error %d", code)
}

// rdataReader reads the fixed width fields of a TSIG RDATA, keeping the first
// error so the parse reads as a straight sequence of fields instead of a
// ladder of length checks.
type rdataReader struct {
	b   []byte
	err error
}

// take returns the next n octets.
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

// uint16 reads a two octet field.
func (r *rdataReader) uint16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// uint48 reads the six octet Time Signed field.
func (r *rdataReader) uint48() uint64 {
	b := r.take(6)
	if b == nil {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(b[2:])) | uint64(binary.BigEndian.Uint16(b[:2]))<<32
}

// name reads an uncompressed name.
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
