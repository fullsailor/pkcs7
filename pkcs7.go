package pkcs7 // import "fullsailor.com/pkcs7"
import (
	"crypto"
	"crypto/hmac"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	_ "crypto/sha1" // for crypto.SHA1
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	info         contentInfo
	Certificates []*x509.Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          signedData
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional"`
}

type unsignedData []byte

var (
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedAndEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	oidDigestedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               asn1.RawValue          `asn1:"optional"`
	CRLs                       []pkix.CertificateList `asn1:"optional"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   pkix.RDNSequence
	SerialNumber *big.Int
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// Parse decodes a DER encoded PKCS7 package
func Parse(data []byte) (p7 *PKCS7, err error) {
	var info contentInfo
	rest, err := asn1.Unmarshal(data, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}
	if err != nil {
		return
	}
	var sd signedData
	asn1.Unmarshal(info.Content.Bytes, &sd)
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return
	}
	for _, crl := range sd.CRLs {
		fmt.Printf("CRLs: %v", crl)
	}
	var content unsignedData
	fmt.Printf("--> Signed Data Version %d\n", sd.Version)
	asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &content)
	return &PKCS7{
		info:         info,
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// Verify checks the signatures of a PKCS7 object
func (p7 *PKCS7) Verify() (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer); err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo) error {
	fmt.Printf("--> Signer Info Version: %d\n", signer.Version)
	if len(signer.AuthenticatedAttributes) > 0 {

		// TODO(fullsailor): First check the content type match
		digest, err := getDigestFromAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
		h := crypto.SHA1.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if !hmac.Equal(digest, computed) {
			return errors.New("pkcs7: Message digest mismatch")
		}
	}
	cert := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if cert == nil {
		return errors.New("pkcs7: No certificate for signer")
	}

	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: signer.AuthenticatedAttributes})
	if err != nil {
		return err
	}
	encodedAttributes = encodedAttributes[3:] // Remove the leading sequence octets
	/*
		fmt.Printf("--> asn.1 attributes %x\n", encodedAttributes)
		h.Write(encodedAttributes)
		messageDigest := h.Sum(nil)
		di := digestInfo{
			Algorithm: signer.DigestAlgorithm,
			Digest:    messageDigest,
		}
		fmt.Printf("--> digestInfo %+v\n", di)
		info, err := asn1.Marshal(di)
		if err != nil {
			return err
		}
		fmt.Printf("--> asn.1 digestInfo %x\n---> length:%d\n", info, len(info))
	*/
	algo := x509.SHA1WithRSA
	return cert.CheckSignature(algo, encodedAttributes, signer.EncryptedDigest)
}

var (
	oidDigestAlgorithmSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidEncryptionAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func getDigestFromAttributes(attributes []attribute) (digest []byte, err error) {
	for _, attr := range attributes {
		if attr.Type.Equal(oidAttributeMessageDigest) {
			_, err = asn1.Unmarshal(attr.Value.Bytes, &digest)
			return
		}
	}
	return nil, errors.New("pkcs7: Missing messageDigest attribute")
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if cert.SerialNumber.Cmp(ias.SerialNumber) == 0 {
			// TODO(fullsailor): Compare Issuer Name & Cert Subject
			return cert
		}
	}
	return nil
}
