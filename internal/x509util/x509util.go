/*
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// package x509 provides utilities for working with x509 types.
package x509util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// SignatureAlgorithmDetailsForOid returns a matching SignatureAlgorithm and
// crypto.Hash function from a provided oid.
func SignatureAlgorithmDetailsForOid(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, crypto.Hash, error) {
	for _, details := range signatureAlgorithmDetails {
		if details.oid.Equal(oid) {
			return details.algo, details.hash, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, crypto.Hash(0),
		fmt.Errorf("could not find SignatureAlgorithm details for oid: %s", oid)
}

// SigningParamsForPublicKey returns the parameters to use for signing.
// If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func SigningParamsForPublicKey(pub interface{}, requestedSigAlgo x509.SignatureAlgorithm) (hashFunc crypto.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType x509.PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		hashFunc = crypto.SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1NullRawValue

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	default:
		err = errors.New("x509: only RSA and ECDSA keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			// copy x509.SignatureAlgorithm.isRSAPSS method
			isRSAPSS := func() bool {
				switch requestedSigAlgo {
				case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
					return true
				default:
					return false
				}
			}
			if isRSAPSS() {
				sigAlgo.Parameters = rsaPSSParameters(hashFunc)
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}

	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// added to Go in 1.9
var asn1NullRawValue = asn1.RawValue{
	Tag: 5, /* ASN.1 NULL */
}

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, oidISOSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, oidSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, oidSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, oidSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See https://tools.ietf.org/html/rfc3447#appendix-A.2.3
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// rsaPSSParameters returns an asn1.RawValue suitable for use as the Parameters
// in an AlgorithmIdentifier that specifies RSA PSS.
func rsaPSSParameters(hashFunc crypto.Hash) asn1.RawValue {
	var hashOID asn1.ObjectIdentifier

	switch hashFunc {
	case crypto.SHA256:
		hashOID = oidSHA256
	case crypto.SHA384:
		hashOID = oidSHA384
	case crypto.SHA512:
		hashOID = oidSHA512
	}

	params := pssParameters{
		Hash: pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1NullRawValue,
		},
		MGF: pkix.AlgorithmIdentifier{
			Algorithm: oidMGF1,
		},
		SaltLength:   hashFunc.Size(),
		TrailerField: 1,
	}

	mgf1Params := pkix.AlgorithmIdentifier{
		Algorithm:  hashOID,
		Parameters: asn1NullRawValue,
	}

	var err error
	params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
	if err != nil {
		panic(err)
	}

	serialized, err := asn1.Marshal(params)
	if err != nil {
		panic(err)
	}

	return asn1.RawValue{FullBytes: serialized}
}
