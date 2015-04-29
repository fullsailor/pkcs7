package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
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
	Certificates []*x509.Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.840.113549.1.7.1), Signed Data (1.2.840.113549.1.7.2),
// and Enveloped Data are supported (1.2.840.113549.1.7.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

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

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional,explicit"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   pkix.RDNSequence
	SerialNumber *big.Int
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
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
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}
	if err != nil {
		return
	}

	fmt.Printf("--> Content Type: %s", info.ContentType)
	switch {
	case info.ContentType.Equal(oidSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(oidEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, err
	}
	for _, crl := range sd.CRLs {
		fmt.Printf("CRLs: %v", crl)
	}
	fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData
	if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
		return nil, err
	}
	// Compound octet string
	if compound.IsCompound {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
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
		fmt.Printf("--> Content to Digest:\n %s", p7.Content)
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if !hmac.Equal(digest, computed) {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
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

	fmt.Printf("--> asn.1 attributes %x\n", encodedAttributes)
	/*
		h := crypto.SHA1.New()
		h.Write(p7.raw.ContentInfo.Content.Bytes)
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
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA & DES supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pk crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	if priv := pk.(*rsa.PrivateKey); priv != nil {
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
}

var oidEncryptionAlgorithmDESCBC = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	if !eci.ContentEncryptionAlgorithm.Algorithm.Equal(oidEncryptionAlgorithmDESCBC) {
		return nil, ErrUnsupportedAlgorithm
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	cypherbytes := eci.EncryptedContent.Bytes
	for {
		var part []byte
		cypherbytes, err = asn1.Unmarshal(cypherbytes, &part)
		buf.Write(part)
		if cypherbytes == nil {
			break
		}
	}
	cyphertext := buf.Bytes()

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != 8 {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}

func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0
	// TODO(fullsailor): Compare Issuer Name & Cert Subject
}

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
