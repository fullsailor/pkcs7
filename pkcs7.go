// Package pkcs7 implements parsing and generation of some PKCS#7 structures.
package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

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
	// Signed Data OIDs
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedAndEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	oidDigestedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest Algorithms
	oidDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature Algorithms
	oidEncryptionAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEncryptionAlgorithmDSA       = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Encryption Algorithms
	oidEncryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidEncryptionAlgorithmAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidEncryptionAlgorithmAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidEncryptionAlgorithmAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
)

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type rawCertificates struct {
	Raw asn1.RawContent
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
	IssuerName   asn1.RawValue
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
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
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

	// fmt.Printf("--> Content Type: %s", info.ContentType)
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
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
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

func (raw rawCertificates) Parse() ([]*x509.Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
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

// Verify is a wrapper around VerifyWithChain() that initializes an empty
// trust store, effectively disabling certificate verification when validating
// a signature.
func (p7 *PKCS7) Verify() (err error) {
	return p7.VerifyWithChain(nil)
}

// VerifyWithChain checks the signatures of a PKCS7 object.
// If truststore is not nil, it also verifies the chain of trust of the end-entity
// signer cert to one of the root in the truststore.
func (p7 *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer, truststore); err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo, truststore *x509.CertPool) (err error) {
	signedData := p7.Content
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return errors.New("pkcs7: No certificate for signer")
	}
	signingTime := time.Now().UTC()
	if len(signer.AuthenticatedAttributes) > 0 {
		// TODO(fullsailor): First check the content type match
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return err
		}
		h := hash.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if subtle.ConstantTimeCompare(digest, computed) != 1 {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
		err = unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeSigningTime, &signingTime)
		if err == nil {
			// signing time found, performing validity check
			if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
				return fmt.Errorf("pkcs7: signing time %q it outside of certificate validity %q to %q",
					signingTime.Format(time.RFC3339),
					ee.NotBefore.Format(time.RFC3339),
					ee.NotBefore.Format(time.RFC3339))
			}
		}
	}
	if truststore != nil {
		_, err = verifyCertChain(ee, p7.Certificates, truststore, signingTime)
		if err != nil {
			return err
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)
	return raw.Bytes, nil
}

func getSignatureAlgorithm(digestEncryption, digest pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, error) {
	if digestEncryption.Algorithm.Equal(oidEncryptionAlgorithmRSA) {
		if digest.Algorithm.Equal(oidDigestAlgorithmSHA1) {
			return x509.SHA1WithRSA, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA256) {
			return x509.SHA256WithRSA, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA384) {
			return x509.SHA384WithRSA, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA512) {
			return x509.SHA512WithRSA, nil
		}
	} else if digestEncryption.Algorithm.Equal(oidEncryptionAlgorithmDSA) {
		if digest.Algorithm.Equal(oidDigestAlgorithmSHA1) {
			return x509.DSAWithSHA1, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA256) {
			return x509.DSAWithSHA256, nil
		}
	} else if digestEncryption.Algorithm.Equal(oidEncryptionAlgorithmECDSAP256) ||
		digestEncryption.Algorithm.Equal(oidEncryptionAlgorithmECDSAP384) ||
		digestEncryption.Algorithm.Equal(oidEncryptionAlgorithmECDSAP521) {
		if digest.Algorithm.Equal(oidDigestAlgorithmSHA1) {
			return x509.ECDSAWithSHA1, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA256) {
			return x509.ECDSAWithSHA256, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA384) {
			return x509.ECDSAWithSHA384, nil
		} else if digest.Algorithm.Equal(oidDigestAlgorithmSHA512) {
			return x509.ECDSAWithSHA512, nil
		}
	}
	return -1, fmt.Errorf("pkcs7: unsupported digest encryption algorithm")
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidDigestAlgorithmSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidDigestAlgorithmSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidDigestAlgorithmSHA512):
		return crypto.SHA512, nil
	}
	return crypto.Hash(0), ErrUnsupportedAlgorithm
}

func getOIDForHash(digestAlg crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch digestAlg {
	case crypto.SHA1:
		return oidDigestAlgorithmSHA1, nil
	case crypto.SHA256:
		return oidDigestAlgorithmSHA256, nil
	case crypto.SHA384:
		return oidDigestAlgorithmSHA384, nil
	case crypto.SHA512:
		return oidDigestAlgorithmSHA512, nil
	default:
		return nil, fmt.Errorf("pkcs7: cannot convert hash to oid, unknown hash algorithm")
	}
}

func getOIDForEncryptionAlgorithm(key crypto.PrivateKey) (asn1.ObjectIdentifier, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return oidEncryptionAlgorithmRSA, nil
	case *ecdsa.PrivateKey:
		switch key.(*ecdsa.PrivateKey).Curve.Params().Name {
		case "P-256":
			return oidEncryptionAlgorithmECDSAP256, nil
		case "P-384":
			return oidEncryptionAlgorithmECDSAP384, nil
		case "P-521":
			return oidEncryptionAlgorithmECDSAP521, nil
		}
	}
	return nil, fmt.Errorf("pkcs7: cannot convert encryption algorithm to oid, unknown private key type %T", key)

}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *x509.Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, DES, DES-EDE3, AES-256-CBC and AES-128-GCM supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	switch pkey.(type) {
	case *rsa.PrivateKey:
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, pkey.(*rsa.PrivateKey), recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(oidEncryptionAlgorithmDESCBC) &&
		!alg.Equal(oidEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		fmt.Printf("Unsupported Content Encryption Algorithm: %s\n", alg)
		return nil, ErrUnsupportedAlgorithm
	}

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var err error

	switch {
	case alg.Equal(oidEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(oidEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(oidEncryptionAlgorithmAES256CBC):
		fallthrough
	case alg.Equal(oidEncryptionAlgorithmAES128GCM), alg.Equal(oidEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
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
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Compare(cert.RawIssuer, ias.IssuerName.FullBytes) == 0
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

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd            signedData
	certs         []*x509.Certificate
	digestAlg     crypto.Hash
	messageDigest []byte
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes []Attribute
}

// NewSignedData is a wrapper around new NewSignedDataWithHash() that initializes
// a signed data struct using the SHA1 hashing algorithm.
func NewSignedData(data []byte) (*SignedData, error) {
	return NewSignedDataWithHash(data, crypto.SHA1)
}

// NewSignedDataWithHash takes data and a hash algorithm and initializes a PKCS7 SignedData
// struct that is ready to be signed via AddSigner. The hash algorithm is a crypto.Hash
// constant of a SHA1/256/384/512 function (eg. `crypto.SHA256`).
func NewSignedDataWithHash(data []byte, digestAlg crypto.Hash) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: oidData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	oid, err := getOIDForHash(digestAlg)
	if err != nil {
		return nil, err
	}
	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: oid,
	}
	h := digestAlg.New()
	h.Write(data)
	md := h.Sum(nil)
	sd := signedData{
		ContentInfo:                ci,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
	}
	return &SignedData{sd: sd, messageDigest: md, digestAlg: digestAlg}, nil
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}

// AddSigner is a wrapper around AddSignerWithParents() that adds a signer without any parent.
func (sd *SignedData) AddSigner(ee *x509.Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
	var parents []*x509.Certificate
	return sd.AddSignerWithParents(ee, pkey, parents, config)
}

// AddSignerWithParents signs attributes about the content and adds certificates
// and signers infos to the Signed Data. The certificate and private
// of the end-entity signer are used to issue the signature, and any
// parent of that end-entity that need to be added to the list of
// certifications can be specified in the parents slice.
//
// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
// section of the SignedData.SignerInfo, alongside the serial number of
// the end-entity.
func (sd *SignedData) AddSignerWithParents(ee *x509.Certificate, pkey crypto.PrivateKey, parents []*x509.Certificate, config SignerInfoConfig) error {
	attrs := &attributes{}
	attrs.Add(oidAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(oidAttributeMessageDigest, sd.messageDigest)
	attrs.Add(oidAttributeSigningTime, time.Now())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}
	signature, err := signAttributes(finalAttrs, pkey, sd.digestAlg)
	if err != nil {
		return err
	}
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	if len(parents) == 0 {
		// no parent, the issue is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	} else {
		err = verifyPartialChain(ee, parents)
		if err != nil {
			return err
		}
		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}
	oidDigestAlg, err := getOIDForHash(sd.digestAlg)
	if err != nil {
		return err
	}
	oidEncryptionAlg, err := getOIDForEncryptionAlgorithm(pkey)
	if err != nil {
		return err
	}
	signer := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestAlg},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEncryptionAlg},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	// create signature of signed attributes
	sd.certs = append(sd.certs, ee)
	sd.certs = append(sd.certs, parents...)
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *x509.Certificate) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: oidSignedData}
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

// verifyCertChain takes an end-entity certs, a list of potential intermediates and a
// truststore, and built all potential chains between the EE and a trusted root.
//
// When verifying chains that may have expired, currentTime can be set to a past date
// to allow the verification to pass. If unset, currentTime is set to the current UTC time.
func verifyCertChain(ee *x509.Certificate, certs []*x509.Certificate, truststore *x509.CertPool, currentTime time.Time) (chains [][]*x509.Certificate, err error) {
	intermediates := x509.NewCertPool()
	for _, intermediate := range certs {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   currentTime,
	}
	chains, err = ee.Verify(verifyOptions)
	if err != nil {
		return chains, fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
	}
	return
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *x509.Certificate, parents []*x509.Certificate) error {
	if len(parents) == 0 {
		return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
	}
	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %v", err)
	}
	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}
	return verifyPartialChain(parents[0], parents[1:])
}

func cert2issuerAndSerial(cert *x509.Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

type ecdsaSignature struct {
	R, S *big.Int // fields must be exported for ASN.1 marshalling
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []attribute, pkey crypto.PrivateKey, digestAlg crypto.Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	h := digestAlg.New()
	h.Write(attrBytes)
	hash := h.Sum(nil)
	switch pkey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, pkey.(*rsa.PrivateKey), digestAlg, hash)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, pkey.(*ecdsa.PrivateKey), hash)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: failed to sign attributes: %v", err)
		}
		return asn1.Marshal(ecdsaSignature{R: r, S: s})
	}
	return nil, fmt.Errorf("pkcs7: unsupported signing key type %T", pkey)
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*x509.Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

// DegenerateCertificate creates a signed data structure containing only the
// provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	emptyContent := contentInfo{ContentType: oidData}
	sd := signedData{
		Version:      1,
		ContentInfo:  emptyContent,
		Certificates: rawCert,
		CRLs:         []pkix.CertificateList{},
	}
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}

const (
	// EncryptionAlgorithmDESCBC is the DES CBC encryption algorithm
	EncryptionAlgorithmDESCBC = iota

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM encryption algorithm
	EncryptionAlgorithmAES128GCM
)

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC and AES-128-GCM supported")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptAES128GCM(content []byte) ([]byte, *encryptedContentInfo, error) {
	// Create AES key and nonce
	key := make([]byte, 16)
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidEncryptionAlgorithmAES128GCM,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptDESCBC(content []byte) ([]byte, *encryptedContentInfo, error) {
	// Create DES key & CBC IV
	key := make([]byte, 8)
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmDESCBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
//
// The algorithm used to perform encryption is determined by the current value
// of the global ContentEncryptionAlgorithm package variable. By default, the
// value is EncryptionAlgorithmDESCBC. To use a different algorithm, change the
// value before calling Encrypt(). For example:
//
//     ContentEncryptionAlgorithm = EncryptionAlgorithmAES128GCM
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func Encrypt(content []byte, recipients []*x509.Certificate) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	// Apply chosen symmetric encryption method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content)

	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAES128GCM(content)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidEncryptionAlgorithmRSA,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: oidEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *x509.Certificate) ([]byte, error) {
	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	return nil, ErrUnsupportedAlgorithm
}
