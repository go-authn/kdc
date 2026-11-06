// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

type manyPeople []*directory.Identity

func (m manyPeople) Identities() ([]*directory.Identity, error) { return m, nil }
func (manyPeople) Describe() string                             { return "many" }
func (manyPeople) Members(string) ([]string, error)             { return nil, nil }

// indexedPeople is manyPeople with a [Finder]: what a source that keeps an
// index by name, as authnd's snapshot does, gives the realm.
type indexedPeople struct {
	manyPeople
	byName map[string]*directory.Identity
}

func newIndexedPeople(m manyPeople) indexedPeople {
	ix := indexedPeople{manyPeople: m, byName: make(map[string]*directory.Identity, len(m))}
	for _, id := range m {
		ix.byName[id.Name()] = id
	}
	return ix
}

func (ix indexedPeople) Find(name string) (*directory.Identity, bool, error) {
	id, ok := ix.byName[name]
	return id, ok, nil
}

func tenThousand() manyPeople {
	var people manyPeople
	for i := 0; i < 10000; i++ {
		people = append(people, directory.NewIdentity(fmt.Sprintf("user%05d", i), directory.WithPassword("pw")))
	}
	return people
}

// BenchmarkASNoPreauth is the cost of the cheapest unauthenticated request
// (PREAUTH_REQUIRED) against a directory of 10 000 people: the lookup walks
// the directory, so this is where the realm's per-request cost lives.
func BenchmarkASNoPreauth(b *testing.B) { benchASNoPreauth(b, tenThousand()) }

// BenchmarkASNoPreauthFinder is the same request against a source that is a
// [Finder]: no walk (go-authn/kdc#31).
func BenchmarkASNoPreauthFinder(b *testing.B) { benchASNoPreauth(b, newIndexedPeople(tenThousand())) }

func benchASNoPreauth(b *testing.B, people directory.Source) {
	kt := keytab.New()
	if err := kt.AddEntry("krbtgt/"+testRealm, testRealm, "k", time.Now(), 2, 18); err != nil {
		b.Fatal(err)
	}
	s, err := New(Config{Realm: testRealm, People: people, Services: kt})
	if err != nil {
		b.Fatal(err)
	}
	// the last person: the worst case of a linear walk
	req := asReq(b, "user09999", []string{"krbtgt", testRealm}, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.handle(req)
	}
}
