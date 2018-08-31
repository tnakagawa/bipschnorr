package bipschnorr_test

import (
	"testing"
	"time"

	"github.com/tnakagawa/bipschnorr"
)

func TestThreshold(te *testing.T) {
	start := time.Now()
	te.Logf("Introduction / %fs", (time.Now().Sub(start)).Seconds())
	k := rndi(9) + 2
	t := rndi(k) + 1
	m := rndbs()
	H := bipschnorr.NewPoint(rndbi())
	users := []*bipschnorr.Tuser{}
	for i := 1; i <= k; i++ {
		user, err := bipschnorr.NewThresholdUser(k, t, i, H)
		if err != nil {
			te.Logf("error : %+v", err)
			te.Fail()
			return
		}
		users = append(users, user)
	}
	te.Logf("The number of users k. %d", k)
	te.Logf("The number of collaborators t. %d", t)
	te.Logf("The constant H refers to the generator. %x", H.Bytes())
	te.Logf("The message m : %x", m)
	te.Logf("Shared Secret / %fs", (time.Now().Sub(start)).Seconds())
	te.Logf("Step 1 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range users {
		C := ui.SharedCommitments()
		for _, uj := range users {
			if ui.Idx() == uj.Idx() {
				continue
			}
			err := uj.SetSharedCommitments(ui.Idx(), C)
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Step 2 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range users {
		for _, uj := range users {
			if ui.Idx() == uj.Idx() {
				continue
			}
			s, sd := ui.SharedSecret(uj.Idx())
			err := uj.SetSharedSecret(ui.Idx(), s, sd, ui.OtherSharedCommitments(uj.Idx()))
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Step 3 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range users {
		A := ui.SharedPoints()
		for _, uj := range users {
			if ui.Idx() == uj.Idx() {
				continue
			}
			err := uj.SetSharedPoints(ui.Idx(), A)
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Signing / %fs", (time.Now().Sub(start)).Seconds())
	tusers := []*bipschnorr.Tuser{}
	ts := []int{}
	for len(tusers) < t {
		i := rndi(len(users))
		tusers = append(tusers, users[i])
		ts = append(ts, users[i].Idx())
		users = append(users[:i], users[i+1:]...)
	}
	te.Logf("Collaborators : %+v", ts)
	for _, user := range tusers {
		user.SetCollaborators(ts)
	}
	te.Logf("Step1 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range tusers {
		C := ui.RandomCommitments()
		for _, uj := range tusers {
			if ui.Idx() == uj.Idx() {
				continue
			}
			err := uj.SetRandomCommitments(ui.Idx(), C)
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Step2 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range tusers {
		for _, uj := range tusers {
			if ui.Idx() == uj.Idx() {
				continue
			}
			r, rd := ui.RandomNumber(uj.Idx())
			err := uj.SetRandomNumber(ui.Idx(), r, rd, ui.OtherRandomCommitments(uj.Idx()))
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Step3 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range tusers {
		B := ui.RandomPoints()
		for _, uj := range tusers {
			if ui.Idx() == uj.Idx() {
				continue
			}
			err := uj.SetRandomPoints(ui.Idx(), B)
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Step4 / %fs", (time.Now().Sub(start)).Seconds())
	for _, ui := range tusers {
		ui.SetMessage(m)
	}
	for _, ui := range tusers {
		sig := ui.Signature()
		for _, uj := range tusers {
			if ui.Idx() == uj.Idx() {
				continue
			}
			err := uj.SetSignature(ui.Idx(), sig)
			if err != nil {
				te.Logf("error : %+v", err)
				te.Fail()
				return
			}
		}
	}
	te.Logf("Step5 / %fs", (time.Now().Sub(start)).Seconds())
	idx := rndi(len(tusers))
	sig := tusers[idx].Signing()
	P := tusers[idx].SharedPublickey()
	te.Logf("Verification / %f s", (time.Now().Sub(start)).Seconds())
	v := bipschnorr.Verification(P, m, sig)
	te.Logf("%d of %d threshold signature : %v / %f s", t, k, v, (time.Now().Sub(start)).Seconds())
	if !v {
		te.Logf("fail verify : %v", v)
		te.Fail()
		return
	}
}
