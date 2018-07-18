// bipschnorrbtcec.go
package bipschnorr

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// VerificationBtcec is
// Input:
// The public key P: a point
// The message m: a 32 byte array
// A signature sig: a 64 byte array
func VerificationBtcec(P *btcec.PublicKey, m []byte, sig []byte) bool {
	if len(m) != 32 {
		return false
	}
	if len(sig) != 64 {
		return false
	}
	// The signature is valid if and only if the algorithm below does not fail.
	// Fail if not oncurve(P).
	if !btcec.S256().IsOnCurve(P.X, P.Y) {
		return false
	}
	// Let r = int(sig[0:32]); fail if r ≥ p.
	r := intbs(sig[0:32])
	if r.Cmp(btcec.S256().P) >= 0 {
		return false
	}
	// Let s = int(sig[32:64]); fail if s ≥ n.
	s := intbs(sig[32:64])
	if s.Cmp(btcec.S256().N) >= 0 {
		return false
	}
	// Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
	e := intbs(hash(ll(bytes(r), P.SerializeCompressed(), m)))
	// sG
	sG := &btcec.PublicKey{}
	sG.X, sG.Y = btcec.S256().ScalarBaseMult(s.Bytes())
	// -eP
	eP := &btcec.PublicKey{}
	eP.X, eP.Y = btcec.S256().ScalarMult(P.X, P.Y, sub(btcec.S256().N, e).Bytes())
	// Let R = sG - eP.
	R := &btcec.PublicKey{}
	R.X, R.Y = btcec.S256().Add(sG.X, sG.Y, eP.X, eP.Y)
	// Fail if infinite(R) or jacobi(y(R)) ≠ 1 or x(R) ≠ r.
	if R.Y.Cmp(big.NewInt(0)) == 0 {
		return false
	}
	if jacobi(R.Y).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	if R.X.Cmp(r) != 0 {
		return false
	}
	return true
}

// Signing is
// Input:
// The secret key d: an integer in the range 1..n-1.
// The message m: an array of 32 bytes
func SigningBtcec(d *btcec.PrivateKey, m []byte) []byte {
	if len(m) != 32 {
		return nil
	}
	// To sign:
	// Let k = int(hash(bytes(d) || m)) mod n.
	k := mod(intbs(hash(ll(bytes(d.D), m))), btcec.S256().N)
	// Let R = kG.
	R := &btcec.PublicKey{}
	R.X, R.Y = btcec.S256().ScalarBaseMult(k.Bytes())
	// If jacobi(y(R)) ≠ 1, let k = n - k.
	if jacobi(R.Y).Cmp(big.NewInt(1)) != 0 {
		k = sub(btcec.S256().N, k)
	}

	// Let e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n.
	e := mod(intbs(hash(ll(bytes(R.X), d.PubKey().SerializeCompressed(), m))), btcec.S256().N)
	// The signature is bytes(x(R)) || bytes(k + ed mod n).
	return ll(bytes(R.X), bytes(mod(add(k, mul(e, d.D)), btcec.S256().N)))
}
