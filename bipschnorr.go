// Package bipschnorr project bipschnorr.go
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
package bipschnorr

import (
	"crypto/sha256"
	"math/big"
)

// Lowercase variables represent integers or byte arrays.

// The constant p refers to the field size, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F.
var p = new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F})

// The constant n refers to the curve order, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141.
var n = new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF,
	0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41})

// Uppercase variables refer to points on the curve with equation y^2 = x^3 + 7 over the integers modulo p.

// Point is EC point.
type Point [2]*big.Int

// NewPoint retuns a point for private key.
func NewPoint(d *big.Int) *Point {
	return pointMul(d, G)
}

// NewPointForPub retuns a point for public key.
func NewPointForPub(pub []byte) *Point {
	if len(pub) != 33 || (pub[0] != 0x02 && pub[0] != 0x03) {
		return nil
	}
	x := new(big.Int).SetBytes(pub[1:])
	y := new(big.Int).ModSqrt(add(exp(x, big.NewInt(3)), big.NewInt(7)), p)
	if y == nil {
		return &Point{}
	}
	if (pub[0] == 0x02 && y.Bit(0) == 1) || (pub[0] == 0x03 && y.Bit(0) == 0) {
		y = mod(sub(p, y), p)
	}
	return &Point{x, y}
}

// Bytes returns compress point bytes.
func (p *Point) Bytes() []byte {
	bs := make([]byte, 1)
	bs[0] = byte(0x02 + y(p).Bit(0))
	return ll(bs, bytes(x(p)))
}

// infinite(P) returns whether or not P is the point at infinity.
func infinite(P *Point) bool {
	if y(P) == nil || y(P).Cmp(big.NewInt(0)) == 0 {
		return true
	}
	return false
}

// x(P) and y(P) refer to the X and Y coordinates of a point P (assuming it is not infinity).
func x(P *Point) *big.Int {
	return P[0]
}

func y(P *Point) *big.Int {
	return P[1]
}

// G is
// The constant G refers to the generator,
// for which x(G) = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
// and y(G) = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8.
var G = &Point{
	new(big.Int).SetBytes([]byte{0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
		0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}),
	new(big.Int).SetBytes([]byte{0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6,
		0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8})}

// oncurve(P) returns whether a point P is on the curve and not infinite.
func oncurve(P *Point) bool {
	if infinite(P) {
		return false
	}
	// y^2 - x^3 = 7
	return new(big.Int).Mod(new(big.Int).Sub(
		new(big.Int).Exp(y(P), big.NewInt(2), p),
		new(big.Int).Exp(x(P), big.NewInt(3), p)),
		p).Cmp(big.NewInt(7)) == 0
}

// Addition of points refers to the usual elliptic curve group operation.
func pointAdd(p1, p2 *Point) *Point {
	if infinite(p1) {
		return p2
	}
	if infinite(p2) {
		return p1
	}
	if (x(p1).Cmp(x(p2)) == 0) && (y(p1).Cmp(y(p2)) != 0) {
		return &Point{}
	}
	var lam *big.Int
	if (x(p1).Cmp(x(p2)) == 0) && (y(p1).Cmp(y(p2)) == 0) {
		// 3 * x1 * x1 * (2 * y1)^(p - 2) mod p
		lam = mod(mul(big.NewInt(3), x(p1), x(p1),
			exp(mul(big.NewInt(2), p1[1]), sub(p, big.NewInt(2)))),
			p)
	} else {
		// (y2 - y1) * (x2 - x1)^(p - 2) mod p
		lam = mod(mul(sub(y(p2), y(p1)),
			exp(sub(x(p2), x(p1)), sub(p, big.NewInt(2)))),
			p)
	}
	x3 := mod(sub(sub(mul(lam, lam), p1[0]), p2[0]), p)
	return &Point{x3, mod(sub(mul(lam, sub(p1[0], x3)), p1[1]), p)}
}

// Multiplication of an integer and a point refers to the repeated application of the group operation.
func pointMul(x *big.Int, p *Point) *Point {
	r := &Point{}
	for i := 0; i < x.BitLen(); i++ {
		if x.Bit(i) == 1 {
			r = pointAdd(r, p)
		}
		p = pointAdd(p, p)
	}
	return r
}

// Functions and operations:

// || refers to byte array concatenation.
func ll(bss ...[]byte) []byte {
	ba := []byte{}
	for _, bs := range bss {
		ba = append(ba, bs...)
	}
	return ba
}

// The function bytes(x), where x is an integer, returns the 32 byte encoding of x, most significant byte first.
func bytes(x *big.Int) []byte {
	bs := make([]byte, 32)
	l := len(x.Bytes())
	if l > len(bs) {
		copy(bs, x.Bytes()[:32])
	} else {
		copy(bs[32-l:], x.Bytes())
	}
	return bs
}

// The function bytes(P), where P is a point, returns byte(0x02 + (y(P) & 1)) || bytes(x(P)).
// Point#Bytes()

// The function int(x), where x is a 32 byte array, returns the 256-bit unsigned integer whose most significant byte encoding is x.
func intbs(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}

// The function x[i:j], where x is a 32 byte array, returns a j - i byte array with a copy of the i-th byte (inclusive) to the j-th byte (exclusive) of x.

// The function hash(x), where x is a byte array, returns the 32 byte SHA256 hash of x.
func hash(x []byte) []byte {
	hash := sha256.Sum256(x)
	return hash[:]
}

// The function jacobi(x), where x is an integer, returns the Jacobi symbol of x / p. It is equal to x(p-1)/2 mod p (Euler's criterion)
func jacobi(x *big.Int) *big.Int {
	z, _ := new(big.Int).QuoRem(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2), big.NewInt(0))
	return exp(x, z)
}

// Verification is
// Input:
// The public key P: a point
// The message m: a 32 byte array
// A signature sig: a 64 byte array
func Verification(P *Point, m []byte, sig []byte) bool {
	if len(m) != 32 {
		return false
	}
	if len(sig) != 64 {
		return false
	}
	// The signature is valid if and only if the algorithm below does not fail.
	// Fail if not oncurve(P).
	if !oncurve(P) {
		return false
	}
	// Let r = int(sig[0:32]); fail if r ≥ p.
	r := intbs(sig[0:32])
	if r.Cmp(p) >= 0 {
		return false
	}
	// Let s = int(sig[32:64]); fail if s ≥ n.
	s := intbs(sig[32:64])
	if s.Cmp(n) >= 0 {
		return false
	}
	// Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
	e := intbs(hash(ll(bytes(r), P.Bytes(), m)))
	// Let R = sG - eP.
	R := pointAdd(pointMul(s, G), pointMul(mod(sub(n, e), n), P))
	// Fail if infinite(R) or jacobi(y(R)) ≠ 1 or x(R) ≠ r.
	if infinite(R) || jacobi(y(R)).Cmp(big.NewInt(1)) != 0 || x(R).Cmp(r) != 0 {
		return false
	}
	return true
}

// Signing is
// Input:
// The secret key d: an integer in the range 1..n-1.
// The message m: an array of 32 bytes
func Signing(d *big.Int, m []byte) []byte {
	if d.Cmp(n) >= 0 {
		return nil
	}
	if len(m) != 32 {
		return nil
	}
	// To sign:
	// Let k = int(hash(bytes(d) || m)) mod n.

	k := mod(intbs(hash(ll(bytes(d), m))), n)
	// Let R = kG.
	R := pointMul(k, G)
	// If jacobi(y(R)) ≠ 1, let k = n - k.
	if jacobi(y(R)).Cmp(big.NewInt(1)) != 0 {
		k = sub(n, k)
	}
	// Let e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n.
	e := mod(intbs(hash(ll(bytes(x(R)), pointMul(d, G).Bytes(), m))), n)
	// The signature is bytes(x(R)) || bytes(k + ed mod n).
	return ll(bytes(x(R)), bytes(mod(add(k, mul(e, d)), n)))
}

// golang big.Int

func mul(bis ...*big.Int) *big.Int {
	m := big.NewInt(1)
	for _, bi := range bis {
		m = new(big.Int).Mul(m, bi)
	}
	return m
}

func mod(x, y *big.Int) *big.Int {
	return new(big.Int).Mod(x, y)
}

func add(x, y *big.Int) *big.Int {
	return new(big.Int).Add(x, y)
}

func sub(x, y *big.Int) *big.Int {
	return new(big.Int).Sub(x, y)
}

func exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, p)
}
