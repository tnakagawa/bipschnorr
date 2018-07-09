package bipschnorr_test

import (
	"bipschnorr"

	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
)

// p is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
var p = new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F})

func TestVector1(t *testing.T) {
	// The following triplets of (public key, message, signature) should pass verification.
	// Furthermore, compliant signers must produce the specified signature given the (private key, message) pair:

	// Test vector 1
	// Private key: 0000000000000000000000000000000000000000000000000000000000000001
	pri, _ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000001", 16)
	// Public key: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	pub := s2p("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	// Signature: 787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05
	sign, _ := hex.DecodeString("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05")

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}

	sig := bipschnorr.SchnorrSign(msg, pri)
	t.Logf("Schnorr_sign:%x", sig)
	if !reflect.DeepEqual(sign, sig) {
		t.Errorf("no match Schnorr_sign")
	}
}

func TestVector2(t *testing.T) {
	// The following triplets of (public key, message, signature) should pass verification.
	// Furthermore, compliant signers must produce the specified signature given the (private key, message) pair:

	// Test vector 2
	// Private key: B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
	pri, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pub := s2p("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}

	sig := bipschnorr.SchnorrSign(msg, pri)
	t.Logf("Schnorr_sign : %x", sig)
	if !reflect.DeepEqual(sign, sig) {
		t.Errorf("no match Schnorr_sign")
	}
}

func TestVector3(t *testing.T) {
	// The following triplets of (public key, message, signature) should pass verification.
	// Furthermore, compliant signers must produce the specified signature given the (private key, message) pair:

	// Test vector 3
	// Private key: C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7
	pri, _ := new(big.Int).SetString("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7", 16)
	// Public key: 03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B
	pub := s2p("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
	// Message: 5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C
	msg, _ := hex.DecodeString("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
	// Signature: 00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380
	sign, _ := hex.DecodeString("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380")

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}

	sig := bipschnorr.SchnorrSign(msg, pri)
	t.Logf("Schnorr_sign : %x", sig)
	if !reflect.DeepEqual(sign, sig) {
		t.Errorf("no match Schnorr_sign")
	}
}

func TestVector4(t *testing.T) {
	// The following triple of (public key, message, signature) should pass verification:

	// Test vector 4
	// Public key: 03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
	pub := s2p("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
	// Message: 4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703
	msg, _ := hex.DecodeString("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
	// Signature: 00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D
	sign, _ := hex.DecodeString("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D")

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}
}

func TestVector5(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 5
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pub := s2p("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7")
	// Reason: incorrect R residuosity

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector6(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 6
	// Public key: 03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B
	pub := s2p("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
	// Message: 5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C
	msg, _ := hex.DecodeString("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
	// Signature: 00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC
	sign, _ := hex.DecodeString("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC")
	// Reason: negated message hash

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector7(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 7
	// Public key: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	pub := s2p("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000	")
	// Signature: 787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C
	sign, _ := hex.DecodeString("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C")
	// Reason: negated s value

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector8(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 8
	// Public key: 03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pub := s2p("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89	")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
	// Reason: negated public key

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector9(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 9
	// Public key: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	pub := s2p("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	// Signature: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC307031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05
	sign, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC307031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05")
	// Reason: negated public key

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector10(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 10
	// Public key: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	pub := s2p("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	// Signature: 787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142
	sign, _ := hex.DecodeString("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142")
	// Reason: negated public key

	v := bipschnorr.SchnorrVerify(msg, pub, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func s2p(str string) []*big.Int {
	bs, _ := hex.DecodeString(str)
	po := make([]*big.Int, 2)
	po[0] = new(big.Int).SetBytes(bs[1:])
	po[1] = new(big.Int).ModSqrt(new(big.Int).Add(new(big.Int).Exp(po[0], big.NewInt(3), p), big.NewInt(7)), p)
	if (bs[0] == 0x02 && po[1].Bit(0) == 1) || (bs[0] == 0x03 && po[1].Bit(0) == 0) {
		po[1] = new(big.Int).Mod(new(big.Int).Sub(p, po[1]), p)
	}
	return po
}