package pkcs7

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"hash"
	"io"

	"golang.org/x/xerrors"
)

// NewDecoder creates stream PKCS7 decoder
func NewDecoder(r io.Reader) *PKCS7 {
	return &PKCS7{
		r: newBerReader(r),
	}
}

func (p7 *PKCS7) buildHashes(dest io.Writer) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		r := io.LimitReader(p7.r, int64(length))
		for _, h := range p7.hashes {
			r = io.TeeReader(r, h)
		}
		if _, err = io.Copy(dest, r); err != nil {
			return xerrors.Errorf("buildHashes: %w", err)
		}
		return nil
	}
}

func (p7 *PKCS7) initHashes(class int, constructed bool, tag int, length int) (err error) {
	if err = p7.r._object(&p7.digestAlgorithmIdentifiers, "set")(class, constructed, tag, length); err != nil {
		return xerrors.Errorf("initHashes: %w", err)
	}
	p7.hashes = make(map[crypto.Hash]hash.Hash)
	for i, aid := range p7.digestAlgorithmIdentifiers {
		hash, err := getHashForOID(aid.Algorithm)
		if err != nil {
			return xerrors.Errorf("initHashes: digest %d: %w", i, err)
		}
		p7.hashes[hash] = hash.New()
	}
	return
}

func (p7 *PKCS7) verifySignature(i int) error {
	var signedData []byte
	signer := p7.Signers[i]
	hashType, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	hash, ok := p7.hashes[hashType]
	if !ok {
		return xerrors.Errorf("hash for signer %d not found", i)
	}
	computed := hash.Sum(nil)
	if len(signer.AuthenticatedAttributes) > 0 {
		// TODO(fullsailor): First check the content type match
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		if !hmac.Equal(digest, computed) {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		// TODO(fullsailor): Optionally verify certificate chain
		// TODO(fullsailor): Optionally verify signingTime against certificate NotAfter/NotBefore
		if signedData, err = marshalAttributes(signer.AuthenticatedAttributes); err != nil {
			return err
		}
	}
	cert := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if cert == nil {
		return xerrors.New("pkcs7: No certificate for signer")
	}

	algo, err := getSignAlgorithm(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	if len(signedData) != 0 {
		return cert.CheckSignature(algo, signedData, signer.EncryptedDigest)
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if isRSAPSS(algo) {
			return rsa.VerifyPSS(pub, hashType, computed, signer.EncryptedDigest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, hashType, computed, signer.EncryptedDigest)
	}
	return xerrors.Errorf("unsupported signature algorithm: %v", algo)
}

// portions Copyright 2009 The Go Authors.
func isRSAPSS(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

// VerifyTo parses underlying message stream and writes extracted content into writer
func (p7 *PKCS7) VerifyTo(dest io.Writer) error {
	br := p7.r
	var version int
	var contentType asn1.ObjectIdentifier
	var certificates rawCertificates
	err := br.readBER(
		br.oid(oidSignedData,
			br.optional(0,
				br.sequence(
					br.object(&version, ""),
					p7.initHashes,
					br.sequence(
						br.object(&contentType, ""),
						br.optional(0,
							br.octets(
								p7.buildHashes(dest),
							),
						),
					),
					br.raw(0, true, func(data []byte) error {
						certificates.Raw = data
						certs, err := certificates.Parse()
						if err != nil {
							return xerrors.Errorf("parse certificates: %w", err)
						}
						p7.Certificates = certs
						return nil
					}),
					br.raw(1, true, func(data []byte) error {
						_, err := asn1.UnmarshalWithParams(data, &p7.CRLs, "optional,tag:1")
						return xerrors.Errorf("unmarshaling CRLs: %w", err)
					}),
					br.object(&p7.Signers, "set"),
				),
			),
		),
	)
	for i := range p7.Signers {
		if err := p7.verifySignature(i); err != nil {
			return err
		}
	}
	return err
}
