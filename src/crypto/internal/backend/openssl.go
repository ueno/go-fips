// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && cgo && !android && !gocrypt && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,cgo,!android,!gocrypt,!cmd_go_bootstrap,!msan,!no_openssl

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the variable Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package backend

import (
	"github.com/golang-fips/openssl-fips/openssl"
)

// Enabled controls whether FIPS crypto is enabled.
var Enabled = openssl.Enabled

// Unreachable marks code that should be unreachable
// when OpenSSLCrypto is in use. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if Enabled() {
		panic("opensslcrypto: invalid code execution")
	}
}

// Provided by runtime.crypto_backend_runtime_arg0 to avoid os import.
func runtime_arg0() string

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

// UnreachableExceptTests marks code that should be unreachable
// when OpenSSLCrypto is in use. It panics.
func UnreachableExceptTests() {
	name := runtime_arg0()
	// If OpenSSLCrypto ran on Windows we'd need to allow _test.exe and .test.exe as well.
	if Enabled() && !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
		println("opensslcrypto: unexpected code execution in", name)
		panic("opensslcrypto: invalid code execution")
	}
}

var ExecutingTest = openssl.ExecutingTest

const RandReader = openssl.RandReader

var NewGCMTLS = openssl.NewGCMTLS
var NewSHA1 = openssl.NewSHA1
var NewSHA224 = openssl.NewSHA224
var NewSHA256 = openssl.NewSHA256
var NewSHA384 = openssl.NewSHA384
var NewSHA512 = openssl.NewSHA512

var SHA1 = openssl.SHA1
var SHA224 = openssl.SHA224
var SHA256 = openssl.SHA256
var SHA384 = openssl.SHA384
var SHA512 = openssl.SHA512

var NewHMAC = openssl.NewHMAC

var NewAESCipher = openssl.NewAESCipher

type PublicKeyECDSA = openssl.PublicKeyECDSA
type PrivateKeyECDSA = openssl.PrivateKeyECDSA

var GenerateKeyECDSA = openssl.GenerateKeyECDSA
var NewPrivateKeyECDSA = openssl.NewPrivateKeyECDSA
var NewPublicKeyECDSA = openssl.NewPublicKeyECDSA
var SignMarshalECDSA = openssl.SignMarshalECDSA
var VerifyECDSA = openssl.VerifyECDSA
var HashVerifyECDSA = openssl.HashVerifyECDSA
var HashSignECDSA = openssl.HashSignECDSA

type PublicKeyECDH = openssl.PublicKeyECDH
type PrivateKeyECDH = openssl.PrivateKeyECDH

var GenerateKeyECDH = openssl.GenerateKeyECDH
var NewPrivateKeyECDH = openssl.NewPrivateKeyECDH
var NewPublicKeyECDH = openssl.NewPublicKeyECDH
var ECDH = openssl.ECDH

type PublicKeyRSA = openssl.PublicKeyRSA
type PrivateKeyRSA = openssl.PrivateKeyRSA

var DecryptRSAOAEP = openssl.DecryptRSAOAEP
var DecryptRSAPKCS1 = openssl.DecryptRSAPKCS1
var DecryptRSANoPadding = openssl.DecryptRSANoPadding
var EncryptRSAOAEP = openssl.EncryptRSAOAEP
var EncryptRSAPKCS1 = openssl.EncryptRSAPKCS1
var EncryptRSANoPadding = openssl.EncryptRSANoPadding
var GenerateKeyRSA = openssl.GenerateKeyRSA
var NewPrivateKeyRSA = openssl.NewPrivateKeyRSA
var NewPublicKeyRSA = openssl.NewPublicKeyRSA
var SignRSAPKCS1v15 = openssl.SignRSAPKCS1v15
var SignRSAPSS = openssl.SignRSAPSS
var VerifyRSAPKCS1v15 = openssl.VerifyRSAPKCS1v15
var VerifyRSAPSS = openssl.VerifyRSAPSS

var ExtractHKDF = openssl.ExtractHKDF
var ExpandHKDF = openssl.ExpandHKDF
var SupportsHKDF = openssl.SupportsHKDF
