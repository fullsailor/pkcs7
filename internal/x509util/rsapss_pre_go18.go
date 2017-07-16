// +build !go1.8

package x509util

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

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
	{x509.DSAWithSHA1, oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
}

func isRSAPSS(requestedSigAlgo x509.SignatureAlgorithm) bool {
	return false
}
