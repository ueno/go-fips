// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto"
	boring "crypto/internal/backend"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	"testing/quick"
)

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

type DecryptPKCS1v15Test struct {
	in, out string
}

// These test vectors were generated with `openssl rsautl -pkcs -encrypt`
var decryptPKCS1v15Tests = []DecryptPKCS1v15Test{
	{
		"gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==",
		"x",
	},
	{
		"Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==",
		"testing.",
	},
	{
		"arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==",
		"testing.\n",
	},
	{
		"WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==",
		"01234567890123456789012345678901234567890123456789012",
	},
}

func TestDecryptPKCS1v15(t *testing.T) {
	if boring.Enabled() {
		t.Skip("skipping PKCS#1 v1.5 encryption test with BoringCrypto")
	}

	decryptionFuncs := []func([]byte) ([]byte, error){
		func(ciphertext []byte) (plaintext []byte, err error) {
			return DecryptPKCS1v15(nil, rsaPrivateKey, ciphertext)
		},
		func(ciphertext []byte) (plaintext []byte, err error) {
			return rsaPrivateKey.Decrypt(nil, ciphertext, nil)
		},
	}

	for _, decryptFunc := range decryptionFuncs {
		for i, test := range decryptPKCS1v15Tests {
			out, err := decryptFunc(decodeBase64(test.in))
			if err != nil {
				t.Errorf("#%d error decrypting: %v", i, err)
			}
			want := []byte(test.out)
			if !bytes.Equal(out, want) {
				t.Errorf("#%d got:%#v want:%#v", i, out, want)
			}
		}
	}
}

func TestEncryptPKCS1v15(t *testing.T) {
	if boring.Enabled() {
		t.Skip("skipping PKCS#1 v1.5 encryption test with BoringCrypto")
	}

	random := rand.Reader
	k := (rsaPrivateKey.N.BitLen() + 7) / 8

	tryEncryptDecrypt := func(in []byte, blind bool) bool {
		if len(in) > k-11 {
			in = in[0 : k-11]
		}

		ciphertext, err := EncryptPKCS1v15(random, &rsaPrivateKey.PublicKey, in)
		if err != nil {
			t.Errorf("error encrypting: %s", err)
			return false
		}

		var rand io.Reader
		if !blind {
			rand = nil
		} else {
			rand = random
		}
		plaintext, err := DecryptPKCS1v15(rand, rsaPrivateKey, ciphertext)
		if err != nil {
			t.Errorf("error decrypting: %s", err)
			return false
		}

		if !bytes.Equal(plaintext, in) {
			t.Errorf("output mismatch: %#v %#v", plaintext, in)
			return false
		}
		return true
	}

	config := new(quick.Config)
	if testing.Short() {
		config.MaxCount = 10
	}
	quick.Check(tryEncryptDecrypt, config)
}

// These test vectors were generated with `openssl rsautl -pkcs -encrypt`
var decryptPKCS1v15SessionKeyTests = []DecryptPKCS1v15Test{
	{
		"e6ukkae6Gykq0fKzYwULpZehX+UPXYzMoB5mHQUDEiclRbOTqas4Y0E6nwns1BBpdvEJcilhl5zsox/6DtGsYg==",
		"1234",
	},
	{
		"Dtis4uk/q/LQGGqGk97P59K03hkCIVFMEFZRgVWOAAhxgYpCRG0MX2adptt92l67IqMki6iVQyyt0TtX3IdtEw==",
		"FAIL",
	},
	{
		"LIyFyCYCptPxrvTxpol8F3M7ZivlMsf53zs0vHRAv+rDIh2YsHS69ePMoPMe3TkOMZ3NupiL3takPxIs1sK+dw==",
		"abcd",
	},
	{
		"bafnobel46bKy76JzqU/RIVOH0uAYvzUtauKmIidKgM0sMlvobYVAVQPeUQ/oTGjbIZ1v/6Gyi5AO4DtHruGdw==",
		"FAIL",
	},
}

func TestEncryptPKCS1v15SessionKey(t *testing.T) {
	if boring.Enabled() {
		t.Skip("skipping PKCS#1 v1.5 encryption test with BoringCrypto")
	}

	for i, test := range decryptPKCS1v15SessionKeyTests {
		key := []byte("FAIL")
		err := DecryptPKCS1v15SessionKey(nil, rsaPrivateKey, decodeBase64(test.in), key)
		if err != nil {
			t.Errorf("#%d error decrypting", i)
		}
		want := []byte(test.out)
		if !bytes.Equal(key, want) {
			t.Errorf("#%d got:%#v want:%#v", i, key, want)
		}
	}
}

func TestEncryptPKCS1v15DecrypterSessionKey(t *testing.T) {
	if boring.Enabled() {
		t.Skip("skipping PKCS#1 v1.5 encryption test with BoringCrypto")
	}

	for i, test := range decryptPKCS1v15SessionKeyTests {
		plaintext, err := rsaPrivateKey.Decrypt(rand.Reader, decodeBase64(test.in), &PKCS1v15DecryptOptions{SessionKeyLen: 4})
		if err != nil {
			t.Fatalf("#%d: error decrypting: %s", i, err)
		}
		if len(plaintext) != 4 {
			t.Fatalf("#%d: incorrect length plaintext: got %d, want 4", i, len(plaintext))
		}

		if test.out != "FAIL" && !bytes.Equal(plaintext, []byte(test.out)) {
			t.Errorf("#%d: incorrect plaintext: got %x, want %x", i, plaintext, test.out)
		}
	}
}

func TestNonZeroRandomBytes(t *testing.T) {
	random := rand.Reader

	b := make([]byte, 512)
	err := nonZeroRandomBytes(b, random)
	if err != nil {
		t.Errorf("returned error: %s", err)
	}
	for _, b := range b {
		if b == 0 {
			t.Errorf("Zero octet found")
			return
		}
	}
}

type signPKCS1v15Test struct {
	in, out string
}

// These vectors have been tested with
//
//	`openssl rsautl -verify -inkey pk -in signature | hexdump -C`
var signPKCS1v15Tests = []signPKCS1v15Test{
	{"Test.\n", "0c7c85d938862248846cba06b06ac9bfe752aafed3092c224f257855006aa35b43d101e6c8e59cbc4c20b07c81552963f189dea700e042d4b70c236a031a29a9273cc138e69dc1a5834491de4822d8cb6acf218789d2586cb0f3892236b0948ffaf8691f6fa04597caa45068f9be39b8ea8b5336a8c94e2696f872120778abcfea711e5fbf75f835f0f5204ccdd020013c2ceae25e9d1378a1d10cf86ca269eef48fee8ebb5e8dfb08f0c48d22d1a7162e080ec1f6e48541288aaaa1f2370f0688cf1786a32abed41df1d3b96b665794bf7a772743fc8b62d73901cea4569494c794a01ccc7dda0d42199f5b58739c0c0e280774b56ccf51993f5ea3d4954319"},
}

func TestSignPKCS1v15(t *testing.T) {
	for i, test := range signPKCS1v15Tests {
		h := sha1.New()
		h.Write([]byte(test.in))
		digest := h.Sum(nil)

		s, err := SignPKCS1v15(nil, boringRsaPrivateKey, crypto.SHA1, digest)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}

		expected, _ := hex.DecodeString(test.out)
		if !bytes.Equal(s, expected) {
			t.Errorf("#%d got: %x want: %x", i, s, expected)
		}
	}
}

func TestVerifyPKCS1v15(t *testing.T) {
	for i, test := range signPKCS1v15Tests {
		h := sha1.New()
		h.Write([]byte(test.in))
		digest := h.Sum(nil)

		sig, _ := hex.DecodeString(test.out)

		err := VerifyPKCS1v15(&boringRsaPrivateKey.PublicKey, crypto.SHA1, digest, sig)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}
	}
}

func TestOverlongMessagePKCS1v15(t *testing.T) {
	ciphertext := decodeBase64("fjOVdirUzFoLlukv80dBllMLjXythIf22feqPrNo0YoIjzyzyoMFiLjAc/Y4krkeZ11XFThIrEvw\nkRiZcCq5ng==")
	_, err := DecryptPKCS1v15(nil, rsaPrivateKey, ciphertext)
	if err == nil {
		t.Error("RSA decrypted a message that was too long.")
	}
}

func TestUnpaddedSignature(t *testing.T) {
	msg := []byte("Thu Dec 19 18:06:16 EST 2013\n")
	// This base64 value was generated with:
	// % echo Thu Dec 19 18:06:16 EST 2013 > /tmp/msg
	// % openssl rsautl -sign -inkey key -out /tmp/sig -in /tmp/msg
	//
	// Where "key" contains the RSA private key given at the bottom of this
	// file.
	expectedSig := decodeBase64("XgDn6nJdfL/gY3eq15l9Va41/nNkDrkTlxOZYHYeFaMOW+Z4BHTCZ1LhqNBXOBK9XEyHho6okpY4rqE1zTIVX/kCGJ+jS6VRgUsHcTcpvKBYZCW84yrjE360gkntzkGxUF9FaiOGzmJKwBm1UvFgFIaYlvF+PdU0H1trBvm/RYRU42xOQRY1U+MSXgruFfINE20vPTlAG22uJ2CELrZUDykQGnrDFsEP0UqyyyiqGqxHt8E7iNYC6+xhPPC/ato9Bev08nu/U/EGH2imifSoNz/IN6h3fQClHwk1a74bPrcRsmUAAHOX2X1VKxK7IruinU8iOyoG6oFuvT+QlMnWAw==")

	sig, err := SignPKCS1v15(nil, boringRsaPrivateKey, crypto.Hash(0), msg)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %s", err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Fatalf("signature is not expected value: got %x, want %x", sig, expectedSig)
	}
	if err := VerifyPKCS1v15(&boringRsaPrivateKey.PublicKey, crypto.Hash(0), msg, sig); err != nil {
		t.Fatalf("signature failed to verify: %s", err)
	}
}

func TestShortSessionKey(t *testing.T) {
	if boring.Enabled() {
		t.Skip("skipping PKCS#1 v1.5 encryption test with BoringCrypto")
	}

	// This tests that attempting to decrypt a session key where the
	// ciphertext is too small doesn't run outside the array bounds.
	ciphertext, err := EncryptPKCS1v15(rand.Reader, &rsaPrivateKey.PublicKey, []byte{1})
	if err != nil {
		t.Fatalf("Failed to encrypt short message: %s", err)
	}

	var key [32]byte
	if err := DecryptPKCS1v15SessionKey(nil, rsaPrivateKey, ciphertext, key[:]); err != nil {
		t.Fatalf("Failed to decrypt short message: %s", err)
	}

	for _, v := range key {
		if v != 0 {
			t.Fatal("key was modified when ciphertext was invalid")
		}
	}
}

// In order to generate new test vectors you'll need the PEM form of this key (and s/TESTING/PRIVATE/):
// -----BEGIN RSA TESTING KEY-----
// MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
// fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
// /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
// RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
// EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
// IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
// tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
// -----END RSA TESTING KEY-----

var rsaPrivateKey = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase10("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077"),
		E: 65537,
	},
	D: fromBase10("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861"),
	Primes: []*big.Int{
		fromBase10("98920366548084643601728869055592650835572950932266967461790948584315647051443"),
		fromBase10("94560208308847015747498523884063394671606671904944666360068158221458669711639"),
	},
}


// This key is generated with the following command:
//
//   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
//
// In order to generate new test vectors you'll need the PEM form of this key (and s/TESTING/PRIVATE/):
// -----BEGIN RSA TESTING KEY-----
// MIIEogIBAAKCAQEAp5qgUIj096pw8U+AjcJucLWenR3oe+tEthXiAuqcYgslW5UU
// lMim34U/h7NbLvbG2KJ2chUsmLtuCFaoIe/YKW5DKm3SPytK/KCBsVa+MQ7zuF/1
// ks5p7yBqFBl6QTekMzwskt/zyDIG9f3A+38akruHNBvUgYqwbWPx4ycclQ52GSev
// /Cfx0I68TGT5SwN/eCJ/ghq3iGAf0mX1bkVaW1seKbL49aAA94KnDCRdl813+S2R
// EPDf2tZwlT0JpZm5QtAqthonZjkjHocZNxhkKF3XWUntE/+l6R4A+CWZlC2vmUc1
// hJTEraksy2JUIjxAaq//FnDpIEVG/N2ofmNpaQIDAQABAoIBAAYH7h9fwkLcNvqz
// 8+oF9k/ndSjtr9UvstYDhRG6S/zKLmK0g1xUOQ7/fjj9lvkiZ6bZd74krWlkizHR
// HnU0KnjZLyEKeR+NSQI8q1YMi0T8JwB6MX3CIDU62x5UiV3p6OZwEqGJXf4U8MOu
// ySAzo2rmxRd2reeobC9Pgp98I47oeqaSRwFVZRPfKk5RvfI7KRmL58BAB0XS56PA
// PJ+3l0fB/oIV11iaBEKildxLDtrvlepQ2KPNf7Dpk0/CPRtS/jxyxIyML8tjR3F0
// KuHplsRjTANyzW/aHddO1fnfnXsVo+0PzSPTHCbxKSu5XmChqsKoB1jM+/tJci4y
// ST5hUXUCgYEAzfA5XEMkR/NNJMfR+FBbdfpQ1b0wqH3qtWZx/tBjKC2Y0XnDQ8ZR
// SEWONLVZMRtTlJaHIPZ9i6anQRR5harrff0OpsKiJUGDout8ehE6eiN8ABWGNlCI
// AiLCerVJZMDcSuDU7xsdHVIdSxYh88Z9g54vUQ4214BG/G0Qm1emV3UCgYEA0FjP
// wq5cEGt9xDCg+oXk0bLm4Wn4FkabJH7M+oCosHHY9W1vgvv50bpNoAbaB5r1mlan
// T6gEtkQPB2juMTnuIwRL+kvOmSKqZGlAsyrq8smTuBUv7brbybkYN3Rg51KV6u1J
// vCdGpMYWHUNRkkQ88cr6iFPodYU+CzRR4ABif6UCgYBc0jDYb/7TW0tjD5mJJZcD
// xw5WOE7NMuvuVT1+T6jRvDOL/yjOzH1oaMle4npQEvQKHgrMBa2ymyv5vmPDprU7
// 9Sp8aW+yASR281MIpelIkePbGdiDdKrI46fqrPlmqzLfoRT4rKzjwVYouNIW0VlT
// UKIdE54OZegY8IOysL/t3QKBgDZnSnECiIW9G80UCaUBO3vKZGFuA1sFutMvzSSI
// XgQc5lNH7TtdwqESLdzgjSQ5QXK4t92j+P8DDI2Zx8DQ6K76G0DTdLImDCpGFZ/z
// UABvxIPn/GjuRyAIlhs852Tf+seqiHt6Igc6tmGTx4QTD3rvzrW0e1ncnhPc6Jg+
// YXoFAoGARD9OPrd4J2N+nkSWif9VOuPHvOXEczwBDJbsAGrOW1kTbDStF0OIVOt0
// Ukj+mnnL8ZNyVLgTrZDRfXvlA94EbPK5/rMAYwjMlXHP8R22ts3eDMNUdw0/Zl1g
// QOhL8wXZcdwHKsONy55kZHo8pmneqi9EnqqLGguLwx5WIMzWvZ8=
// -----END RSA TESTING KEY-----
var boringRsaPrivateKey = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase10("21158045964626271357192122217374656030758659027828186070945904292001900400536015683616588162432995042444433048358489684754391937856768687035719252953024200424710141144247332111111703450451053746470714834263970345645429072182468402024496704681563920755701016821908901551953007428010372679515325239834996680088335364047952157190852800612876331418656069309925009888436309603986985085994522668542367909534919143332035879812534342880780397552183153129074979881038274141387521146813437241354454755076987809231514974999721446583492285447433481905074857761363232069067710471781475338676103917736574576264372309657208790149481"),
		E: 65537,
	},
	D: fromBase10("761340340511160175596965412196526886865993372482350730149506062172718946847796801591296809955561141932718681604153505639135828424412541864931030231418425021767439619656396706456340306422726055474229263742664572190035142125430003037585933958150329067887329644632294232035234749334047352968048823517110653841610552935776850272326662981899080407723586223365381844237920705656687458814241284694808178926597606445541251131238479373288091835422103855191540510255449923931942356040157416183921500123257314690876170989779091557025781299703525522541564460824444942813697278129203778499396891927458901143348340382342458724725"),
	Primes: []*big.Int{
		fromBase10("144614845075019407477413542397453717313067325100413366253445573263534965103596714687177264872359318890824353359027245467187809258188745722502749049155303133577880462309749004261724896311777040275474974736908034246705034289232466323779271534051780280366551238605398407358839369487962557838147775245147196249973"),
		fromBase10("146306182837940795154243491672545598732731521261772425577071902398494756400761181229877966908959767779942799478853764354255505873530749881845000716071915494302715554511619294255599209521952152229250381623079574375248555498847701822870266575429060940749806104053368129657146195126647000200158517816035847077797"),
	},
}

func TestShortPKCS1v15Signature(t *testing.T) {
	pub := &PublicKey{
		E: 65537,
		N: fromBase10("8272693557323587081220342447407965471608219912416565371060697606400726784709760494166080686904546560026343451112103559482851304715739629410219358933351333"),
	}
	sig, err := hex.DecodeString("193a310d0dcf64094c6e3a00c8219b80ded70535473acff72c08e1222974bb24a93a535b1dc4c59fc0e65775df7ba2007dd20e9193f4c4025a18a7070aee93")
	if err != nil {
		t.Fatalf("failed to decode signature: %s", err)
	}

	h := sha256.Sum256([]byte("hello"))
	err = VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	if err == nil {
		t.Fatal("VerifyPKCS1v15 accepted a truncated signature")
	}
}
