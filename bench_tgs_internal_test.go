// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// BenchmarkTGSReq is one valid TGS-REQ end to end. 1024 distinct requests (one
// authenticator each, cusec 0..1023) are built up front and served in turn;
// the replay cache, when there is one, is emptied before each round so that
// every request is a first sighting, and its growth from empty is part of the
// figure.
func BenchmarkTGSReq(b *testing.B) {
	s := benchServer(b)
	const n = 1024
	reqs := make([][]byte, n)
	tgtSName := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	start := time.Now().Add(-time.Minute)
	tkt, sk, err := messages.NewTicket(client, testRealm, tgtSName, testRealm, types.NewKrbFlags(), s.cfg.Services,
		defaultEtype, 2, start, start, start.Add(10*time.Hour), time.Time{})
	if err != nil {
		b.Fatal(err)
	}
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  start.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}}
	bb, err := body.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	et, _ := crypto.GetEtype(sk.KeyType)
	ck, err := et.GetChecksumHash(sk.KeyValue, bb, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		b.Fatal(err)
	}
	for i := range reqs {
		auth := types.Authenticator{AVNO: iana.PVNO, CRealm: testRealm, CName: client, Cusec: i, CTime: now().UTC(),
			SeqNumber: 1, Cksum: types.Checksum{CksumType: et.GetHashID(), Checksum: ck}}
		ab, _ := auth.Marshal()
		ed, err := crypto.GetEncryptedData(ab, sk, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR, 0)
		if err != nil {
			b.Fatal(err)
		}
		apb, _ := (&messages.APReq{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REQ, APOptions: types.NewKrbFlags(),
			Ticket: tkt, EncryptedAuthenticator: ed}).Marshal()
		req := messages.TGSReq{KDCReqFields: messages.KDCReqFields{PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REQ,
			PAData:  types.PADataSequence{{PADataType: patype.PA_TGS_REQ, PADataValue: apb}},
			ReqBody: body}}
		if reqs[i], err = req.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%n == 0 {
			resetReplay(s)
		}
		if out := s.handle(reqs[i%n]); len(out) == 0 {
			b.Fatal("no reply")
		}
	}
}

func benchServer(b *testing.B) *Server {
	b.Helper()
	return testServerTB(b, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
}

func testServerTB(tb testing.TB, id *directory.Identity) *Server {
	tb.Helper()
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(p, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			tb.Fatal(err)
		}
	}
	s, err := New(Config{Realm: testRealm, People: onlyOne{id}, Services: kt})
	if err != nil {
		tb.Fatal(err)
	}
	return s
}
