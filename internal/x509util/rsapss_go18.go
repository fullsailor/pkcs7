// +build go1.8

package x509util

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

var signatureAlgorithmDetails = []struct {
	algo         x509.SignatureAlgorithm
	oidDigest    asn1.ObjectIdentifier
	oidSignature asn1.ObjectIdentifier
	pubKeyAlgo   x509.PublicKeyAlgorithm
	hash         crypto.Hash
}{
	{x509.MD2WithRSA, oidMD2, oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, oidMD5, oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, oidSHA1, oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, oidSHA1, oidISOSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, oidSHA256, oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, oidSHA384, oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, oidSHA512, oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, oidSHA256, oidSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, oidSHA384, oidSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, oidSHA512, oidSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, oidSHA1, oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, oidSHA256, oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSHA1, oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSHA256, oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSHA384, oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSHA512, oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
}

func isRSAPSS(requestedSigAlgo x509.SignatureAlgorithm) bool {
	switch requestedSigAlgo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}
