package bipschnorr

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Tuser is
type Tuser struct {
	k    int
	t    int
	i    int
	H    *Point
	m    []byte
	a    []*big.Int
	ad   []*big.Int
	As   [][]*Point
	Cs   [][]*Point
	ss   []*big.Int
	sds  []*big.Int
	ts   []int
	b    []*big.Int
	bd   []*big.Int
	Bs   [][]*Point
	Cds  [][]*Point
	rs   []*big.Int
	rds  []*big.Int
	sigs []*big.Int
}

// NewThresholdUser returns Tuser
func NewThresholdUser(k, t, i int, H *Point) (*Tuser, error) {
	// TODO validate parameters
	user := &Tuser{}
	user.k = k
	user.t = t
	user.i = i
	user.H = H
	user.Cs = make([][]*Point, k)
	user.ss = make([]*big.Int, k)
	user.sds = make([]*big.Int, k)
	user.As = make([][]*Point, k)
	user.Cds = make([][]*Point, t)
	user.rs = make([]*big.Int, t)
	user.rds = make([]*big.Int, t)
	user.Bs = make([][]*Point, t)
	user.sigs = make([]*big.Int, t)
	return user, nil
}

// Idx returns index of user.
func (user *Tuser) Idx() int {
	return user.i
}

// SharedCommitments returns commitments of shared secret.
func (user *Tuser) SharedCommitments() []*Point {
	if user.Cs[user.i-1] != nil {
		return user.Cs[user.i-1]
	}
	// a_{i0} ... a_{i(t-1)}
	// a'_{i0} ... a'_{i(t-1)}
	Cs := []*Point{}
	for i := 0; i < user.t; i++ {
		a := rnd()
		ad := rnd()
		user.a = append(user.a, a)
		user.ad = append(user.ad, ad)
		// C = aG + a'G
		C := pointAdd(pointMul(a, G), pointMul(ad, user.H))
		Cs = append(Cs, C)
	}
	user.Cs[user.i-1] = Cs
	// s_{ii} = f_i(x) = a_{i0} + a_{i1}x^1 + ... + a_{i(t-1)}x^{t-1}
	user.ss[user.i-1] = polynomial(user.i, user.a)
	// s'_{ii} = f'_i(x) = a'_{i0} + a'_{i1}x^1 + ... + a'_{i(t-1)}x^{t-1}
	user.sds[user.i-1] = polynomial(user.i, user.ad)
	return user.Cs[user.i-1]
}

// SetSharedCommitments sets commitments of shared secret for user(j).
func (user *Tuser) SetSharedCommitments(j int, C []*Point) error {
	// TODO validate parameters
	user.Cs[j-1] = C
	return nil
}

// SharedSecret returns shared secret for user(j).
func (user *Tuser) SharedSecret(j int) (*big.Int, *big.Int) {
	// TODO validate parameter
	// s_{ij} = f_i(j) = a_{i0} + a_{i1}j^1 + ... + a_{i(t-1)}j^{t-1}
	s := polynomial(j, user.a)
	// s'_{ij} = f'_i(j) = a'_{i0} + a'_{i1}j^1 + ... + a'_{i(t-1)}j^{t-1}
	sd := polynomial(j, user.ad)
	return s, sd
}

// OtherSharedCommitments returns other user's commitments of shared secret.
func (user *Tuser) OtherSharedCommitments(j int) [][]*Point {
	// TODO validate parameter
	Cs := [][]*Point{}
	for i, C := range user.Cs {
		if (user.Idx() == i+1) || (j == i+1) {
			continue
		}
		Cs = append(Cs, C)
	}
	return Cs
}

// SetSharedSecret verifies and sets shared secret for user(j) and other commitments.
func (user *Tuser) SetSharedSecret(j int, s, sd *big.Int, ocs [][]*Point) error {
	// TODO validate parameter
	// sG + s'H
	sGsdH := pointAdd(pointMul(s, G), pointMul(sd, user.H))
	// i^0C_{j0} + ... + i^(t-1)C_{j(t-1)}
	S := &Point{}
	for i, C := range user.Cs[j-1] {
		S = pointAdd(S, pointMul(expn(user.Idx(), i), C))
	}
	if !bseq(sGsdH.Bytes(), S.Bytes()) {
		return fmt.Errorf("invalid ShareSignature. %d", j)
	}
	hi := 0
	for h := 1; h <= user.k; h++ {
		if h == user.i || h == j {
			continue
		}
		for i := range ocs[hi] {
			if !bseq(ocs[hi][i].Bytes(), user.Cs[h-1][i].Bytes()) {
				return fmt.Errorf("illegal other commitment. %d %d", hi+1, i)
			}
		}
		hi++
	}
	user.ss[j-1] = s
	user.sds[j-1] = sd
	return nil
}

// SharedPoints returns shared points.
func (user *Tuser) SharedPoints() []*Point {
	if user.As[user.i-1] != nil {
		return user.As[user.i-1]
	}
	// A_{i0}...A_{i(t-1)}
	As := []*Point{}
	for _, a := range user.a {
		// A = aG
		A := pointMul(a, G)
		As = append(As, A)
	}
	user.As[user.i-1] = As
	return user.As[user.i-1]
}

// SetSharedPoints verifies and sets shared points.
func (user *Tuser) SetSharedPoints(j int, As []*Point) error {
	// TODO validate parameter
	// sG
	sG := pointMul(user.ss[j-1], G)
	// i^0A_{j0} + ... + i^(t-1)A_{j(t-1)}
	sum := &Point{}
	for i, A := range As {
		sum = pointAdd(sum, pointMul(expn(user.Idx(), i), A))
	}
	if !bseq(sG.Bytes(), sum.Bytes()) {
		return fmt.Errorf("invalid shared publickeys. %d", j)
	}
	user.As[j-1] = As
	return nil
}

// SharedPublickey returns shared publickey.
func (user *Tuser) SharedPublickey() *Point {
	pub := &Point{}
	// P = A_{10} + ... + A_{k0}
	for _, a := range user.As {
		if len(a) == 0 {
			return nil
		}
		pub = pointAdd(pub, a[0])
	}
	return pub
}

// SetCollaborators sets collaborators.
func (user *Tuser) SetCollaborators(ts []int) error {
	// TODO validate parameter
	user.ts = ts
	// if len(ts) == 1 {
	// 	user.RandomCommitments()
	// 	user.RandomPoints()
	// }
	return nil
}

// cidx returns index of collaborators.
func (user *Tuser) cidx(j int) int {
	idx := -1
	for i, t := range user.ts {
		if j == t {
			idx = i
			break
		}
	}
	return idx
}

// RandomCommitments returns commitments of random point.
func (user *Tuser) RandomCommitments() []*Point {
	i := user.cidx(user.i)
	if i < 0 {
		return nil
	}
	if user.Cds[i] != nil {
		return user.Cds[i]
	}
	// b_{i_u0} ... b_{i_u(t-1)}
	// b'_{i_u0} ... b'_{i_u(t-1)}
	Cds := []*Point{}
	for i := 0; i < user.t; i++ {
		b := rnd()
		bd := rnd()
		user.b = append(user.b, b)
		user.bd = append(user.bd, bd)
		Cd := pointAdd(pointMul(b, G), pointMul(bd, user.H))
		Cds = append(Cds, Cd)
	}
	user.Cds[i] = Cds
	user.rs[i] = polynomial(user.i, user.b)
	user.rds[i] = polynomial(user.i, user.bd)
	return user.Cds[i]
}

// SetRandomCommitments sets commitments of random point for user(j).
func (user *Tuser) SetRandomCommitments(j int, Cd []*Point) error {
	// TODO validate parameters
	idx := user.cidx(j)
	if idx < 0 {
		return fmt.Errorf("not found user(%d)", j)
	}
	user.Cds[idx] = Cd
	return nil
}

// RandomNumber returns random number for user(j).
func (user *Tuser) RandomNumber(j int) (*big.Int, *big.Int) {
	// TODO validate parameter
	r := polynomial(j, user.b)
	rd := polynomial(j, user.bd)
	return r, rd
}

// OtherRandomCommitments gets other commitments of shared publickey.
func (user *Tuser) OtherRandomCommitments(j int) [][]*Point {
	// TODO validate parameter
	cds := [][]*Point{}
	for i, t := range user.ts {
		if (user.Idx() == t) || (j == t) {
			continue
		}
		cds = append(cds, user.Cds[i])
	}
	return cds
}

// SetRandomNumber a
func (user *Tuser) SetRandomNumber(j int, r, rd *big.Int, ocds [][]*Point) error {
	// TODO validate parameters
	idx := user.cidx(j)
	if idx < 0 {
		return nil
	}
	// rG + r'H
	rGrdH := pointAdd(pointMul(r, G), pointMul(rd, user.H))
	// i^0C_{j0} + ... + i^(t-1)C_{j(t-1)}
	sum := &Point{}
	for i, Cd := range user.Cds[idx] {
		sum = pointAdd(sum, pointMul(expn(user.Idx(), i), Cd))
	}
	if !bseq(rGrdH.Bytes(), sum.Bytes()) {
		return fmt.Errorf("invalid RandomNumber. %d", j)
	}
	oi := 0
	for h, t := range user.ts {
		if t == user.i || t == j {
			continue
		}
		for i := range ocds[oi] {
			if !bseq(ocds[oi][i].Bytes(), user.Cds[h][i].Bytes()) {
				return fmt.Errorf("illegal other commitment. %d %d", oi+1, t)
			}
		}
		oi++
	}
	user.rs[idx] = r
	user.rds[idx] = rd
	return nil
}

// RandomPoints returns random points.
func (user *Tuser) RandomPoints() []*Point {
	i := user.cidx(user.i)
	if i < 0 {
		return nil
	}
	if user.Bs[i] != nil {
		return user.Bs[i]
	}
	Bs := []*Point{}
	for _, b := range user.b {
		B := pointMul(b, G)
		Bs = append(Bs, B)
	}
	user.Bs[i] = Bs
	return user.Bs[i]
}

// SetRandomPoints verifies and sets random points.
func (user *Tuser) SetRandomPoints(j int, Bs []*Point) error {
	// TODO validate parameters
	idx := user.cidx(j)
	if idx < 0 {
		return nil
	}
	// rG
	rG := pointMul(user.rs[idx], G)
	// i^0A_{j0} + ... + i^(t-1)A_{j(t-1)}
	sum := &Point{}
	for i, B := range Bs {
		sum = pointAdd(sum, pointMul(expn(user.Idx(), i), B))
	}
	if !bseq(rG.Bytes(), sum.Bytes()) {
		return fmt.Errorf("invalid shared publickeys. %d", j)
	}
	user.Bs[idx] = Bs
	return nil
}

// RandomPoint returns random point.
func (user *Tuser) RandomPoint() *Point {
	pub := &Point{}
	for _, b := range user.Bs {
		if len(b) == 0 {
			return nil
		}
		pub = pointAdd(pub, b[0])
	}
	return pub
}

// SetMessage sets message.
func (user *Tuser) SetMessage(m []byte) {
	// TODO validate parameter
	user.m = m
}

// Signature returns signature.
func (user *Tuser) Signature() *big.Int {
	// TODO check internal variable
	i := user.Idx()
	k := big.NewInt(0)
	for _, r := range user.rs {
		k = mod(add(k, r), n)
	}
	R := user.RandomPoint()
	if jacobi(y(R)).Cmp(big.NewInt(1)) != 0 {
		k = sub(n, k)
	}
	P := user.SharedPublickey()
	e := mod(intbs(hash(ll(bytes(x(R)), P.Bytes(), user.m))), n)
	sig := big.NewInt(0)
	for _, s := range user.ss {
		sig = mod(add(sig, s), n)
	}
	sig = mod(add(k, mul(e, sig)), n)
	idx := user.cidx(i)
	fmt.Printf("Set Sig %d %d %x\n", user.Idx(), idx, sig)
	user.sigs[idx] = sig
	return sig
}

// SetSignature verifies and sets signature for user(j).
func (user *Tuser) SetSignature(j int, sig *big.Int) error {
	// TODO check internal variable
	idx := user.cidx(j)
	if idx < 0 {
		return fmt.Errorf("not found user(%d)", j)
	}
	Bsum := &Point{}
	for _, Bs := range user.Bs {
		for i, B := range Bs {
			Bsum = pointAdd(Bsum, pointMul(expn(j, i), B))
		}
	}
	R := user.RandomPoint()
	if jacobi(y(R)).Cmp(big.NewInt(1)) != 0 {
		Bsum = pointMul(mod(big.NewInt(-1), n), Bsum)
	}
	P := user.SharedPublickey()
	e := mod(intbs(hash(ll(bytes(x(R)), P.Bytes(), user.m))), n)
	Asum := &Point{}
	for _, As := range user.As {
		for i, A := range As {
			Asum = pointAdd(Asum, pointMul(expn(j, i), A))
		}
	}
	gG := pointMul(sig, G)
	BHA := pointAdd(Bsum, pointMul(e, Asum))
	if !bseq(gG.Bytes(), BHA.Bytes()) {
		return fmt.Errorf("invalid signature")
	}
	user.sigs[idx] = sig
	return nil
}

// Signing returns signature.
func (user *Tuser) Signing() []byte {
	// TODO check internal variable
	s := big.NewInt(0)
	for j := range user.sigs {
		o := big.NewInt(1)
		for _, t := range user.ts {
			if t == user.ts[j] {
				continue
			}
			de := new(big.Int).ModInverse(sub(big.NewInt(int64(t)), big.NewInt(int64(user.ts[j]))), n)
			o = mod(mul(o, mul(big.NewInt(int64(t)), de)), n)
		}
		s = mod(add(s, mul(o, user.sigs[j])), n)
	}
	R := user.RandomPoint()
	return ll(bytes(x(R)), bytes(s))
}

// polynomial returns f(x) = as[0]x^0 + as[1]x^1 + ... + as[n-1]x^{n-1}
func polynomial(x int, as []*big.Int) *big.Int {
	y := big.NewInt(0)
	for i, a := range as {
		y = mod(add(y, mul(a, expn(x, i))), n)
	}
	return y
}

// rnd returns a byte array of length 32.
func rnd() *big.Int {
	bs := make([]byte, 32)
	rand.Read(bs)
	r := new(big.Int).Mod(new(big.Int).SetBytes(bs), n)
	return r
}

// expn returns x^y mod n.
func expn(x, y int) *big.Int {
	return new(big.Int).Exp(big.NewInt(int64(x)), big.NewInt(int64(y)), n)
}

// bseq returns true if bs1 is equal bs2.
func bseq(bs1, bs2 []byte) bool {
	if len(bs1) != len(bs2) {
		return false
	}
	for i := range bs1 {
		if bs1[i] != bs2[i] {
			return false
		}
	}
	return true
}
