package ecdsa

import (
	"crypto"
	"crypto/internal/boring"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func testHashSignAndHashVerify(t *testing.T, c elliptic.Curve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if priv == nil {
		t.Fatal(err)
	}

	msg := []byte("testing")
	h := crypto.SHA256
	r, s, err := HashSign(rand.Reader, priv, msg, h)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if !HashVerify(&priv.PublicKey, msg, r, s, h) {
		t.Errorf("%s: Verify failed", tag)
	}

	msg[0] ^= 0xff
	if HashVerify(&priv.PublicKey, msg, r, s, h) {
		t.Errorf("%s: Verify should not have succeeded", tag)
	}
}
func TestHashSignAndHashVerify(t *testing.T) {
	testHashSignAndHashVerify(t, elliptic.P256(), "p256")

	if testing.Short() && !boring.Enabled {
		return
	}
	testHashSignAndHashVerify(t, elliptic.P384(), "p384")
	testHashSignAndHashVerify(t, elliptic.P521(), "p521")
}
