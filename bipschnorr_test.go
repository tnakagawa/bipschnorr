package bipschnorr_test

import (
	"github.com/tnakagawa/bipschnorr"

	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
)

func TestVector1(t *testing.T) {
	// The following triplets of (public key, message, signature) should pass verification.
	// Furthermore, compliant signers must produce the specified signature given the (private key, message) pair:

	// Test vector 1
	// Private key: 0000000000000000000000000000000000000000000000000000000000000001
	pri, _ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000001", 16)
	// Public key: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	pubbs, _ := hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	// Signature: 787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05
	sign, _ := hex.DecodeString("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05")

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}

	sig := bipschnorr.Signing(pri, msg)
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
	pubbs, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}

	sig := bipschnorr.Signing(pri, msg)
	t.Logf("Schnorr_sign:%x", sig)
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
	pubbs, _ := hex.DecodeString("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C
	msg, _ := hex.DecodeString("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
	// Signature: 00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380
	sign, _ := hex.DecodeString("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380")

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}

	sig := bipschnorr.Signing(pri, msg)
	t.Logf("Schnorr_sign:%x", sig)
	if !reflect.DeepEqual(sign, sig) {
		t.Errorf("no match Schnorr_sign")
	}
}

func TestVector4(t *testing.T) {
	// The following triple of (public key, message, signature) should pass verification:

	// Test vector 4
	// Public key: 03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
	pubbs, _ := hex.DecodeString("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703
	msg, _ := hex.DecodeString("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
	// Signature: 00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D
	sign, _ := hex.DecodeString("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D")

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}
}

func TestVector4B(t *testing.T) {
	// The following triple of (public key, message, signature) should pass verification:

	// Test vector 4B
	// Public key: 031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F
	pubbs, _ := hex.DecodeString("031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	// Signature: 52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187
	sign, _ := hex.DecodeString("52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187")

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if !v {
		t.Errorf("fail Schnorr_verify : %+v", v)
	}
}

func TestVector5(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 5
	// Public key: 03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
	pubbs, _ := hex.DecodeString("03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703
	msg, _ := hex.DecodeString("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
	// Signature: 00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D
	sign, _ := hex.DecodeString("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D")
	// Reason: public key not on the curve

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector6(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 6
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pubbs, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7")
	// Reason: incorrect R residuosity

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector7(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 7
	// Public key: 03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B
	pubbs, _ := hex.DecodeString("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C
	msg, _ := hex.DecodeString("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
	// Signature: 00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC
	sign, _ := hex.DecodeString("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC")
	// Reason: negated message hash

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector8(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 8
	// Public key: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	pubbs, _ := hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 0000000000000000000000000000000000000000000000000000000000000000
	msg, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000	")
	// Signature: 787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C
	sign, _ := hex.DecodeString("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C")
	// Reason: negated s value

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector9(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 9
	// Public key: 03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pubbs, _ := hex.DecodeString("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
	// Reason: negated public key

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector10(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 10
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pubbs, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D8C3428869A663ED1E954705B020CBB3E7BB6AC31965B9EA4C73E227B17C5AF5A
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D8C3428869A663ED1E954705B020CBB3E7BB6AC31965B9EA4C73E227B17C5AF5A")
	// Reason: sG - eP is infinite

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector11(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 11
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pubbs, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD
	sign, _ := hex.DecodeString("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
	// Reason: sig[0:32] is not an X coordinate on the curve

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector12(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 12
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pubbs, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD
	sign, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
	// Reason: sig[0:32] is equal to field size

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}

func TestVector13(t *testing.T) {
	// The following triples of (public key, message, signature) should not pass verification.

	// Test vector 13
	// Public key: 02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
	pubbs, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pub := bipschnorr.NewPointForPub(pubbs)
	// Message: 243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	// Signature: 2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	sign, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	// Reason: sig[32:64] is equal to curve order

	v := bipschnorr.Verification(pub, msg, sign)
	t.Logf("Schnorr_verify : %v", v)
	if v {
		t.Errorf("success Schnorr_verify : %+v", v)
	}
}
