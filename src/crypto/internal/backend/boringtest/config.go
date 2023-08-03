/* Test configuration package for OpenSSL FIPS

The FIPS mode behavior of OpenSSL varies between versions and distributions
depending which version of the FIPS standard the library targets. Because
the Go crypto tests can not reliably account for these behavioral differences,
building golang-fips on a new distribution often results in test failures due to
variations in things like supported crypto algorithms and key sizes.

The goal of this package is to implement a compile-time defined configuration
for the behavior of OpenSSL, which is more easily configurable to run in different
environments.  The compile-time schema was chosen as the preferred method, because
we don't want elements of the run-time environment to impact the result of the tests
(for example, changes to the environment or config files).
*/

package boringtest

import (
	"testing"
)

var testConfig map[string]bool

func init() {
	testConfig = map[string]bool{
		"PKCSv1.5": false,
		"SHA1": false,
		// really this is anything < 2048
		"RSA1024": false,
		"RSA4096LeafCert": true,
		"RSA1024LeafCert": false,
		"TLS13": true,
		"CurveP224": true,
		"CurveP256": true,
		"CurveP384": true,
		"CurveP521": true,
	}
}

func Supports(t *testing.T, key string) bool {
	result, ok := testConfig[key]
	if !ok {
		return true
	}
	return result
}
