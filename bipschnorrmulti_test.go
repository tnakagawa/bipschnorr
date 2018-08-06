package bipschnorr_test

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/tnakagawa/bipschnorr"

	"github.com/btcsuite/btcd/btcec"

	"testing"
)

func TestMultisignature(t *testing.T) {
	start := time.Now()
	t.Logf("Introduction / %fs", (time.Now().Sub(start)).Seconds())
	u := rndi(10) + 2
	m := rndbs()
	users := []*bipschnorr.Muser{}
	for i := 1; i <= u; i++ {
		d := rndbi()
		user, err := bipschnorr.NewMultiUser(i, u, d, m)
		if err != nil {
			t.Logf("error : %+v", err)
			t.Fail()
			return
		}
		users = append(users, user)
	}
	t.Logf("Step1 / %fs", (time.Now().Sub(start)).Seconds())
	for i := range users {
		for j := range users {
			if i == j {
				continue
			}
			users[j].SetPublicKey(i+1, users[i].PublicKey())
		}
	}
	P, err := users[0].P()
	if err != nil {
		t.Logf("error : %+v", err)
		t.Fail()
		return
	}
	t.Logf("u : %d", u)
	t.Logf("P : %x", P.Bytes())
	t.Logf("m : %x", m)
	t.Logf("Step2 / %fs", (time.Now().Sub(start)).Seconds())
	for i := range users {
		for j := range users {
			if i == j {
				continue
			}
			users[j].SetHash(i+1, users[i].Hash())
		}
	}
	t.Logf("Step3 / %fs", (time.Now().Sub(start)).Seconds())
	for i := range users {
		for j := range users {
			if i == j {
				continue
			}
			users[j].SetRandomPoint(i+1, users[i].RandomPoint())
		}
	}
	t.Logf("Step4 / %fs", (time.Now().Sub(start)).Seconds())
	for i := range users {
		err := users[i].CheckHash()
		if err != nil {
			t.Logf("error : %+v", err)
			t.Fail()
			return
		}
	}
	for i := range users {
		for j := range users {
			if i == j {
				continue
			}
			s, err := users[i].Sign()
			if err != nil {
				t.Logf("error : %+v", err)
				t.Fail()
				return
			}
			users[j].SetSign(i+1, s)
		}
	}
	t.Logf("Step5 / %fs", (time.Now().Sub(start)).Seconds())
	for i := range users {
		err := users[i].CheckSign()
		if err != nil {
			t.Logf("error : %+v", err)
			t.Fail()
			return
		}
	}
	t.Logf("Step6 / %fs", (time.Now().Sub(start)).Seconds())
	i := rndi(u)
	sig, err := users[i].Signing()
	if err != nil {
		t.Logf("error : %+v", err)
		t.Fail()
		return
	}
	v := bipschnorr.Verification(P, m, sig)
	t.Logf("Verification:%v / %fs", v, (time.Now().Sub(start)).Seconds())
	if !v {
		t.Logf("fail verify : %v", v)
		t.Fail()
		return
	}
}

func rndbs() []byte {
	bs := make([]byte, 32)
	rand.Read(bs)
	return bs
}

func rndbi() *big.Int {
	r := new(big.Int).Mod(new(big.Int).SetBytes(rndbs()), btcec.S256().N)
	return r
}

func rndi(n int) int {
	r := new(big.Int).Mod(rndbi(), big.NewInt(int64(n)))
	return int(r.Int64())
}
