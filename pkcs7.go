package pkcs7 // import "fullsailor.com/pkcs7"
import (
	"crypto"
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
	raw          interface{}
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

type signerInfo struct {
	Version               int `asn1:"default:1"`
	IssuerAndSerialNumber struct {
		IssuerName   pkix.RDNSequence
		SerialNumber *big.Int
	}
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
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
	cert := p7.Certificates[0]
	algo := x509.SHA1WithRSA
	signer := p7.Signers[0]
	//content := append(p7.Content, p7.Signers[0].AuthenticatedAttributes.Bytes...)
	/*
		digest, err := getDigestFromAttributes(p7.Signers[0].AuthenticatedAttributes)
		if err != nil {
			return
		}
		fmt.Printf("---> provided message digest: %+v\n", digest)

		h := crypto.SHA1.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		fmt.Printf("---> computed message digest: %+v\n", computed)

		auth, err := asn1.Marshal(p7.Signers[0].AuthenticatedAttributes)
		if err != nil {
			return
		}
		fmt.Printf("---> auth bytes: %+v\n", auth)
	*/
	h := crypto.SHA1.New()
	h.Write(p7.Content)
	h.Write(signer.AuthenticatedAttributes.Bytes)
	messageDigest := h.Sum(nil)
	di := digestInfo{
		Algorithm: signer.DigestAlgorithm, Digest: messageDigest,
	}
	info, err := asn1.Marshal(di)
	if err != nil {
		return
	}
	return cert.CheckSignature(algo, info, signer.EncryptedDigest)
}

func verifySignature(p7 *PKCS7, signer signerInfo) err {

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
