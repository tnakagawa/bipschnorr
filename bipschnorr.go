// Package bipschnorr project bipschnorr.go
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
package bipschnorr

import (
	hash "crypto/sha256"
	"math/big"
)

// p is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
var p = new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F})

// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
var n = new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF,
	0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41})

// G is (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
//       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
var G = []*big.Int{
	new(big.Int).SetBytes([]byte{0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
		0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}),
	new(big.Int).SetBytes([]byte{0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6,
		0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8})}

func pointAdd(p1, p2 []*big.Int) []*big.Int {
	if p1 == nil {
		return p2
	}
	if p2 == nil {
		return p1
	}
	if (p1[0].Cmp(p2[0]) == 0) && (p1[1].Cmp(p2[1]) != 0) {
		return nil
	}
	var lam *big.Int
	if (p1[0].Cmp(p2[0]) == 0) && (p1[1].Cmp(p2[1]) == 0) {
		lam = new(big.Int).Mod(
			mul(big.NewInt(3), p1[0], p1[0],
				new(big.Int).Exp(mul(big.NewInt(2), p1[1]),
					new(big.Int).Sub(p, big.NewInt(2)), p)),
			p)
	} else {
		lam = new(big.Int).Mod(
			mul(new(big.Int).Sub(p2[1], p1[1]),
				new(big.Int).Exp(new(big.Int).Sub(p2[0], p1[0]),
					new(big.Int).Sub(p, big.NewInt(2)), p)),
			p)
	}
	x3 := new(big.Int).Mod(
		new(big.Int).Sub(new(big.Int).Sub(mul(lam, lam), p1[0]), p2[0]),
		p)
	return []*big.Int{x3, new(big.Int).Mod(
		new(big.Int).Sub(mul(lam, new(big.Int).Sub(p1[0], x3)), p1[1]),
		p)}
}

func pointMul(p []*big.Int, n *big.Int) []*big.Int {
	var r []*big.Int
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			r = pointAdd(r, p)
		}
		p = pointAdd(p, p)
	}
	return r
}

func bytesPoint(p []*big.Int) []byte {
	bs := make([]byte, 33)
	if p[1].Bit(0) == 1 {
		bs[0] = byte(0x03)
	} else {
		bs[0] = byte(0x02)
	}
	copy(bs[1:], p[0].Bytes())
	return bs
}

func sha256(bs []byte) *big.Int {
	hash := hash.Sum256(bs)
	return new(big.Int).SetBytes(hash[:])
}

func onCurve(point []*big.Int) bool {
	return new(big.Int).Mod(new(big.Int).Sub(
		new(big.Int).Exp(point[1], big.NewInt(2), p),
		new(big.Int).Exp(point[0], big.NewInt(3), p)),
		p).Cmp(big.NewInt(7)) == 0
}

func jacobi(x *big.Int) *big.Int {
	z, _ := new(big.Int).QuoRem(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2), big.NewInt(0))
	return new(big.Int).Exp(x, z, p)
}

// SchnorrSign returns schnorr signature.
func SchnorrSign(msg []byte, seckey *big.Int) []byte {
	k := sha256(append(bs32(seckey.Bytes()), msg...))
	R := pointMul(G, k)
	if jacobi(R[1]).Cmp(big.NewInt(1)) != 0 {
		k = new(big.Int).Sub(n, k)
	}
	e := sha256(append(append(bs32(R[0].Bytes()), bytesPoint(pointMul(G, seckey))...),
		msg...))
	return append(bs32(R[0].Bytes()),
		bs32(new(big.Int).Mod(new(big.Int).Add(k, mul(e, seckey)), n).Bytes())...)
}

// SchnorrVerify returns verification result.
func SchnorrVerify(msg []byte, pubkey []*big.Int, sig []byte) bool {
	if !onCurve(pubkey) {
		return false
	}
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Cmp(p) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	e := sha256(append(append(bs32(sig[0:32]), bytesPoint(pubkey)...), msg...))
	R := pointAdd(pointMul(G, s), pointMul(pubkey, new(big.Int).Sub(n, e)))
	if R == nil || jacobi(R[1]).Cmp(big.NewInt(1)) != 0 || R[0].Cmp(r) != 0 {
		return false
	}
	return true
}

func mul(bis ...*big.Int) *big.Int {
	m := big.NewInt(1)
	for _, bi := range bis {
		m = new(big.Int).Mul(m, bi)
	}
	return m
}

func bs32(bs []byte) []byte {
	bs32 := make([]byte, 32)
	copy(bs32[len(bs32)-len(bs):], bs)
	return bs32
}
