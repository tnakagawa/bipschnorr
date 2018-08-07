package bipschnorr

import (
	"fmt"
	"math/big"
)

// Muser is user for multisignatures.
type Muser struct {
	i  int      // index of user
	u  int      // number of users
	d  *big.Int // secret key
	m  []byte   // message
	ps []*Point // public keys of all users
	hs [][]byte // hash values of all users
	rs []*Point // random points of all users
	ss [][]byte // signs of all users
}

// NewMultiUser returns Muser.
func NewMultiUser(i, u int, d *big.Int, m []byte) (*Muser, error) {
	if u < 1 || i < 1 || i > u || d == nil || m == nil {
		return nil, fmt.Errorf("illeagl parameter")
	}
	user := &Muser{}
	user.i = i
	user.u = u
	user.d = d
	user.m = m
	user.ps = make([]*Point, u)
	user.hs = make([][]byte, u)
	user.rs = make([]*Point, u)
	user.ss = make([][]byte, u)
	return user, nil
}

// PublicKey returns the public key.
func (u *Muser) PublicKey() *Point {
	return pointMul(u.d, G)
}

// SetPublicKey sets a public key of users.
func (u *Muser) SetPublicKey(i int, pubkey *Point) error {
	if i < 1 || u.u < i || pubkey == nil {
		return fmt.Errorf("illegal parameter")
	}
	u.ps[i-1] = pubkey
	return nil
}

// Hash returns the hash value of the random point.
func (u *Muser) Hash() []byte {
	return hash(u.RandomPoint().Bytes())
}

// SetHash sets a public key of users.
func (u *Muser) SetHash(i int, h []byte) error {
	if i < 1 || u.u < i || h == nil {
		return fmt.Errorf("illegal parameter")
	}
	u.hs[i-1] = h
	return nil
}

// RandomPoint returns the random point.
func (u *Muser) RandomPoint() *Point {
	k := mod(intbs(hash(ll(bytes(u.d), u.m))), n)
	R := pointMul(k, G)
	return R
}

// SetRandomPoint sets a random point of users.
func (u *Muser) SetRandomPoint(i int, R *Point) error {
	if i < 1 || u.u < i || R == nil {
		return fmt.Errorf("illegal parameter")
	}
	u.rs[i-1] = R
	return nil
}

// CheckHash checks hashes of users.
func (u *Muser) CheckHash() error {
	for j := range u.rs {
		if u.i == j+1 {
			continue
		}
		Rj := u.rs[j]
		hj := u.hs[j]
		if Rj == nil || hj == nil {
			return fmt.Errorf("not received random point or hash value from the user(%d)", j+1)
		}
		h := hash(Rj.Bytes())
		for i := range h {
			if hj[i] != h[i] {
				return fmt.Errorf("unmatch hash")
			}
		}
	}
	return nil
}

// Sign returns the sign.
func (u *Muser) Sign() ([]byte, error) {
	R, err := u.sumR()
	if err != nil {
		return nil, err
	}
	k := mod(intbs(hash(ll(bytes(u.d), u.m))), n)
	if jacobi(y(R)).Cmp(big.NewInt(1)) != 0 {
		k = sub(n, k)
	}
	P, err := u.P()
	if err != nil {
		return nil, err
	}
	e := mod(intbs(hash(ll(bytes(x(R)), P.Bytes(), u.m))), n)
	s := bytes(mod(add(k, mul(e, u.d)), n))
	return s, nil
}

// SetSign sets a sign of users.
func (u *Muser) SetSign(i int, s []byte) error {
	if i < 1 || u.u < i || s == nil {
		return fmt.Errorf("illegal parameter")
	}
	u.ss[i-1] = s
	return nil
}

// CheckSign checks signs of users.
func (u *Muser) CheckSign() error {
	R, err := u.sumR()
	if err != nil {
		return err
	}
	P, err := u.P()
	if err != nil {
		return err
	}
	e := mod(intbs(hash(ll(bytes(x(R)), P.Bytes(), u.m))), n)
	// -e
	me := sub(n, e)
	for j := range u.ss {
		if u.i == j+1 {
			continue
		}
		Pj := u.ps[j]
		Rj := u.rs[j]
		if u.ss[j] == nil || Pj == nil || Rj == nil {
			return fmt.Errorf("not received public key , random point or sign from the user(%d)", j+1)
		}
		sj := intbs(u.ss[j])
		// Fail if sj ≥ n.
		if sj.Cmp(n) >= 0 {
			return fmt.Errorf("sign from user(%d) is over", j+1)
		}
		R := pointAdd(pointMul(sj, G), pointMul(me, Pj))
		if infinite(R) || x(R).Cmp(x(Rj)) != 0 {
			return fmt.Errorf("fail to check sign")
		}
	}
	return nil
}

// Signing returns the multisignature.
func (u *Muser) Signing() ([]byte, error) {
	R, err := u.sumR()
	if err != nil {
		return nil, err
	}
	sign, err := u.Sign()
	if err != nil {
		return nil, err
	}
	s := intbs(sign)
	for j := range u.ss {
		if u.i == j+1 {
			continue
		}
		if u.ss[j] == nil {
			return nil, fmt.Errorf("not received sign from the user(%d)", j+1)
		}
		sj := intbs(u.ss[j])
		s = mod(add(s, sj), n)
	}
	return ll(bytes(x(R)), bytes(s)), nil
}

func (u *Muser) sumR() (*Point, error) {
	R := u.RandomPoint()
	for j, r := range u.rs {
		if u.i == j+1 {
			continue
		}
		if r == nil {
			return nil, fmt.Errorf("not received random point from the user(%d)", j+1)
		}
		R = pointAdd(R, r)
	}
	return R, nil
}

// P returns public key for multisignature.
func (u *Muser) P() (*Point, error) {
	P := u.PublicKey()
	for j, p := range u.ps {
		if u.i == j+1 {
			continue
		}
		if p == nil {
			return nil, fmt.Errorf("not received public key from the user(%d)", j+1)
		}
		P = pointAdd(P, p)
	}
	return P, nil
}
