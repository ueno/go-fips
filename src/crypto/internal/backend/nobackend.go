// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux || !cgo || android || cmd_go_bootstrap || msan || no_openssl
// +build !linux !cgo android cmd_go_bootstrap msan no_openssl

package backend

import (
	"crypto"
	"crypto/cipher"
	"crypto/internal/boring/sig"
	"hash"
	"io"
	"math/big"

	"github.com/golang-fips/openssl-fips/openssl"
)

func init() {
	strictFIPSNonCompliantBinaryCheck()
}

var enabled = false

// Unreachable marks code that should be unreachable
// when BoringCrypto is in use. It is a no-op without BoringCrypto.
func Unreachable() {
	// Code that's unreachable when using BoringCrypto
	// is exactly the code we want to detect for reporting
	// standard Go crypto.
	sig.StandardCrypto()
}

// UnreachableExceptTests marks code that should be unreachable
// when BoringCrypto is in use. It is a no-op without BoringCrypto.
func UnreachableExceptTests() {}

func ExecutingTest() bool { return false }

// This is a noop withotu BoringCrytpo.
func PanicIfStrictFIPS(v interface{}) {}

type randReader int

func (randReader) Read(b []byte) (int, error) { panic("boringcrypto: not available") }

const RandReader = randReader(0)

func Enabled() bool   { return false }
func NewSHA1() hash.Hash   { panic("boringcrypto: not available") }
func NewSHA224() hash.Hash { panic("boringcrypto: not available") }
func NewSHA256() hash.Hash { panic("boringcrypto: not available") }
func NewSHA384() hash.Hash { panic("boringcrypto: not available") }
func NewSHA512() hash.Hash { panic("boringcrypto: not available") }
func SHA1(_ []byte) [20]byte { panic("boringcrypto: not available") }
func SHA224(_ []byte) [28]byte { panic("boringcrypto: not available") }
func SHA256(_ []byte) [32]byte { panic("boringcrypto: not available") }
func SHA384(_ []byte) [48]byte { panic("boringcrypto: not available") }
func SHA512(_ []byte) [64]byte { panic("boringcrypto: not available") }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash { panic("boringcrypto: not available") }

func NewAESCipher(key []byte) (cipher.Block, error) { panic("boringcrypto: not available") }

type PublicKeyECDSA struct{ _ int }
type PrivateKeyECDSA struct{ _ int }

func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	panic("boringcrypto: not available")
}
func GenerateKeyECDSA(curve string) (X, Y, D openssl.BigInt, err error) {
	panic("boringcrypto: not available")
}
func NewPrivateKeyECDSA(curve string, X, Y, D openssl.BigInt) (*PrivateKeyECDSA, error) {
	panic("boringcrypto: not available")
}
func NewPublicKeyECDSA(curve string, X, Y openssl.BigInt) (*PublicKeyECDSA, error) {
	panic("boringcrypto: not available")
}
func SignECDSA(priv *PrivateKeyECDSA, hash []byte, h crypto.Hash) (r, s openssl.BigInt, err error) {
	panic("boringcrypto: not available")
}
func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func VerifyECDSA(pub *PublicKeyECDSA, hash, sig []byte) bool {
	panic("boringcrypto: not available")
}

type PublicKeyECDH struct{ _ int }
type PrivateKeyECDH struct{ _ int }
func (pc *PublicKeyECDH) Bytes() []byte { panic("boringcrypto: not available") }
func (pc *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) { panic("boringcrypto: not available") }

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	panic("boringcrypto: not available")
}
func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	panic("boringcrypto: not available")
}
func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	panic("boringcrypto: not available")
}
func SharedKeyECDH(priv *PrivateKeyECDH, peerPublicKey []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	panic("boringcrypto: not available")
}

type PublicKeyRSA struct{ _ int }
type PrivateKeyRSA struct{ _ int }

func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv openssl.BigInt, err error) {
	panic("boringcrypto: not available")
}
func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv openssl.BigInt) (*PrivateKeyRSA, error) {
	panic("boringcrypto: not available")
}
func NewPublicKeyRSA(N, E openssl.BigInt) (*PublicKeyRSA, error) { panic("boringcrypto: not available") }
func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, msgHashed bool) ([]byte, error) {
	panic("boringcrypto: not available")
}
func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("boringcrypto: not available")
}
func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, msgHashed bool) error {
	panic("boringcrypto: not available")
}
func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	panic("boringcrypto: not available")
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	panic("boringcrypto: not available")
}
func SupportsHKDF() bool {
	panic("boringcrypto: not available")
}
func HashVerifyECDSA(pub *PublicKeyECDSA, msg []byte, r, s *big.Int, h crypto.Hash) bool {
	panic("boringcrypto: not available")
}
func HashSignECDSA(priv *PrivateKeyECDSA, hash []byte, h crypto.Hash) (*big.Int, *big.Int, error) {
	panic("boringcrypto: not available")
}
