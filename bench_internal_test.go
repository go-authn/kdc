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

// BenchmarkASNoPreauth is the cost of the cheapest unauthenticated request
// (PREAUTH_REQUIRED) against a directory of 10 000 people: the lookup walks
// the directory, so this is where the realm's per-request cost lives.
func BenchmarkASNoPreauth(b *testing.B) {
	kt := keytab.New()
	if err := kt.AddEntry("krbtgt/"+testRealm, testRealm, "k", time.Now(), 2, 18); err != nil {
		b.Fatal(err)
	}
	var people manyPeople
	for i := 0; i < 10000; i++ {
		people = append(people, directory.NewIdentity(fmt.Sprintf("user%05d", i), directory.WithPassword("pw")))
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
