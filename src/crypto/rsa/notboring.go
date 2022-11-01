// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build no_openssl

package rsa

import boring "crypto/internal/backend"

func boringPublicKey(*PublicKey) (*boring.PublicKeyRSA, error) {
	panic("!no_openssl: not available")
}
func boringPrivateKey(*PrivateKey) (*boring.PrivateKeyRSA, error) {
	panic("!no_openssl: not available")
}
