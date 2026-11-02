package kdc

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// The replay cache of the ticket-granting service.
//
// RFC 4120 3.2.3 (the server's side of an AP-REQ) says an authenticator is
// good once: the server keeps the authenticators it has accepted for as long
// as the clock-skew window lets one be accepted, and refuses a second copy
// with KRB_AP_ERR_REPEAT (34). 3.3.2 makes the PA-TGS-REQ of a TGS-REQ an
// AP-REQ, so the KDC is the server whose cache this is. MIT keeps it in
// lib/krb5/rcache (the "dfl" cache): an entry is the client, the server, the
// authenticator's ctime and its cusec, and an entry older than the skew is
// forgotten.
//
// ⛔ What is bounded, and what is not. The cache holds at most
// [Config.ReplayCacheEntries] entries of 40 bytes each (a SHA-256 of the
// identity and an expiry), plus the map's own overhead: a few megabytes at the
// default, never more. Only a request whose authenticator already decrypted
// under the TGT's session key, carries a valid checksum over the request and
// is inside the skew reaches it, so it is filled by holders of a TGT, not by
// anybody on the network. When it is full of entries that have not expired,
// a new authenticator is REFUSED with KDC_ERR_SVC_UNAVAILABLE (retry later),
// never accepted unchecked and never admitted at the cost of forgetting an
// older one: a replay cache that forgets under pressure is one an attacker
// empties. One sweep a second drops the expired entries.
//
// Not kept: the reply. MIT's lookaside (kdc/dispatch.c) answers a
// retransmitted request with the reply it already made; this cache cannot, so
// a client that retransmits the byte-identical request because it lost the
// reply is refused KRB_AP_ERR_REPEAT. A client that builds a fresh
// authenticator for each attempt is not affected.

// DefaultReplayCacheEntries is [Config.ReplayCacheEntries] when it is zero:
// 65 536 authenticators inside one skew window, which is 218 TGS-REQs a second
// sustained over the default five minutes.
const DefaultReplayCacheEntries = 65536

// replayVerdict is what the cache says about an authenticator.
type replayVerdict int

const (
	replayFresh  replayVerdict = iota // never seen: remembered now
	replayRepeat                      // seen inside its window
	replayFull                        // not seen, and no room to remember it
)

type replayCache struct {
	mu        sync.Mutex
	max       int
	seen      map[[32]byte]int64 // key -> unix nanoseconds after which it is forgotten
	nextSweep int64
}

func newReplayCache(max int) *replayCache {
	if max <= 0 {
		max = DefaultReplayCacheEntries
	}
	return &replayCache{max: max}
}

// replayKey is MIT's rcache key: client, server, ctime, cusec.
func replayKey(crealm, client, server string, ctime time.Time, cusec int) [32]byte {
	var buf [256]byte
	b := append(buf[:0], crealm...)
	b = append(b, 0)
	b = append(b, client...)
	b = append(b, 0)
	b = append(b, server...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, uint64(ctime.Unix()))
	b = binary.BigEndian.AppendUint64(b, uint64(cusec))
	return sha256.Sum256(b)
}

// admit records the authenticator under key, to be forgotten at expires.
func (c *replayCache) admit(key [32]byte, expires, at time.Time) replayVerdict {
	nowNs := at.UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[[32]byte]int64)
	}
	if nowNs >= c.nextSweep {
		for k, exp := range c.seen {
			if exp <= nowNs {
				delete(c.seen, k)
			}
		}
		c.nextSweep = nowNs + int64(time.Second)
	}
	if exp, ok := c.seen[key]; ok && exp > nowNs {
		return replayRepeat
	}
	if _, ok := c.seen[key]; !ok && len(c.seen) >= c.max {
		return replayFull
	}
	c.seen[key] = expires.UnixNano()
	return replayFresh
}

// len is the number of entries held, for tests.
func (c *replayCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
