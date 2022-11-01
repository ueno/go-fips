package ecdsa

import (
	"crypto"
	boring "crypto/internal/backend"
	"crypto/internal/randutil"
	"math/big"
	"io"
)

func HashSign(rand io.Reader, priv *PrivateKey, msg []byte, h crypto.Hash) (*big.Int, *big.Int, error) {
	randutil.MaybeReadByte(rand)

	if boring.Enabled() {
		b, err := boringPrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		return boring.HashSignECDSA(b, msg, h)
	}
	boring.UnreachableExceptTests()

	hash := h.New()
	hash.Write(msg)
	d := hash.Sum(nil)

	return Sign(rand, priv, d)
}

func HashVerify(pub *PublicKey, msg []byte, r, s *big.Int, h crypto.Hash) bool {
	if boring.Enabled() {
		bpk, err := boringPublicKey(pub)
		if err != nil {
			return false
		}
		return boring.HashVerifyECDSA(bpk, msg, r, s, h)
	}
	boring.UnreachableExceptTests()

	hash := h.New()
	hash.Write(msg)
	d := hash.Sum(nil)

	return Verify(pub, d, r, s)
}
