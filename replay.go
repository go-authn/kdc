package kdc

import (
	"sync"
	"time"
)

// The lookaside cache: a request that arrives again, byte for byte, is
// answered with the reply it already had.
//
// It is MIT's (krb5 src/kdc/replay.c, used by src/kdc/dispatch.c), ported:
// the key is the whole request packet; a hit resends the stored reply; a
// request still being worked on when its copy arrives is recorded with no
// reply and the copy is dropped; only a reply that is not a KRB-ERROR is
// stored; an entry is stale two minutes after it went in; the entries together
// are held under 10 MiB, the oldest discarded first.
//
// ⛔ It is NOT a replay cache, and must not become one. RFC 4120 3.2.3 has a
// server remember authenticators and refuse a second copy with
// KRB_AP_ERR_REPEAT, but MIT's KDC turns that off for the TGS on purpose
// (src/kdc/kdc_util.c, kdc_process_tgs_req: "Don't use a replay cache"): a
// client that lost a reply over UDP sends the SAME bytes again, and a
// KRB_AP_ERR_REPEAT then fails a kinit or a kvno that should have worked. Nor
// does a replayer gain anything: the reply is sealed under the TGT's session
// key or the client's long-term key, which a replayer does not hold. What a
// replay costs is the work of answering it, and that is what this saves.
//
// A KRB-ERROR is never stored, so a client told KDC_ERR_SVC_UNAVAILABLE that
// retries the same bytes is served afresh once the directory is back, rather
// than handed the outage again.

const (
	// lookasideMaxSize is MIT's LOOKASIDE_MAX_SIZE.
	lookasideMaxSize = 10 << 20
	// lookasideStale is MIT's STALE_TIME.
	lookasideStale = 2 * time.Minute
	// lookasideEntryOverhead stands for MIT's sizeof(struct entry): the
	// bookkeeping around the two packets, so that empty replies still count.
	lookasideEntryOverhead = 64
)

// lookasideEntry is one request, linked into the expiration queue by its own
// prev and next: an entry is the only allocation a request adds besides the
// copy of its bytes that keys the map.
type lookasideEntry struct {
	req        string
	rep        []byte // nil while the request is being worked on
	in         time.Time
	prev, next *lookasideEntry
}

func (e *lookasideEntry) size() int { return lookasideEntryOverhead + len(e.req) + len(e.rep) }

type lookaside struct {
	mu         sync.Mutex
	entries    map[string]*lookasideEntry
	head, tail *lookasideEntry // oldest first
	size       int
}

func newLookaside() *lookaside {
	return &lookaside{entries: make(map[string]*lookasideEntry)}
}

// enter is kdc_check_lookaside followed, on a miss, by the in-progress
// kdc_insert_lookaside: one lock, so two copies arriving together cannot both
// miss. hit says the request was seen; rep is its reply, nil if it is still
// being worked on.
func (c *lookaside) enter(req []byte) (rep []byte, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[string(req)]; ok {
		// ⛔ One departure from MIT, whose check does not look at the age: an
		// entry there answers until an insertion happens to purge it, which on
		// a quiet KDC is any time at all. Here two minutes is a bound.
		if !now().After(e.in.Add(lookasideStale)) {
			return e.rep, true
		}
		c.discard(e)
	}
	c.insert(&lookasideEntry{req: string(req), in: now()})
	return nil, false
}

// finish is finish_dispatch_cache: the in-progress entry goes, and the reply
// comes in in its place if it is one worth resending. The in-progress entry
// is reused for it, key and all — the same as MIT's remove and insert, without
// a second copy of the request.
func (c *lookaside) finish(req, rep []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[string(req)]
	if ok && e.rep == nil {
		c.discard(e)
	} else {
		e = nil
	}
	if !isReply(rep) {
		return
	}
	if e == nil {
		e = &lookasideEntry{req: string(req)}
	}
	e.rep, e.in = rep, now()
	c.insert(e)
}

// insert is kdc_insert_lookaside: purge from the oldest end while entries are
// stale or the new one would not fit, then append.
func (c *lookaside) insert(e *lookasideEntry) {
	for old := c.head; old != nil; old = c.head {
		if !e.in.After(old.in.Add(lookasideStale)) && c.size+e.size() <= lookasideMaxSize {
			break
		}
		c.discard(old)
	}
	if prev, ok := c.entries[e.req]; ok {
		c.discard(prev)
	}
	e.prev, e.next = c.tail, nil
	if c.tail != nil {
		c.tail.next = e
	} else {
		c.head = e
	}
	c.tail = e
	c.entries[e.req] = e
	c.size += e.size()
}

func (c *lookaside) discard(e *lookasideEntry) {
	c.size -= e.size()
	delete(c.entries, e.req)
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

// len is the number of entries held, for tests.
func (c *lookaside) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// isReply says a reply is an AS-REP or a TGS-REP, the two MIT stores (it
// stores on a zero code, and a KRB-ERROR is a non-zero one): an ASN.1
// APPLICATION tag 11 or 13, constructed, as the first byte (RFC 4120 5.4.2).
// KRB-ERROR is APPLICATION 30.
func isReply(rep []byte) bool {
	return len(rep) > 0 && (rep[0] == 0x6b || rep[0] == 0x6d)
}
