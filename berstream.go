package pkcs7

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"

	"github.com/pkg/errors"
)

type berReader struct {
	*bufio.Reader
	bytesRead int
}

func newBerReader(r io.Reader) *berReader {
	return &berReader{Reader: bufio.NewReader(r)}
}

func (br *berReader) ReadByte() (res byte, err error) {
	if res, err = br.Reader.ReadByte(); err == nil {
		br.bytesRead++
	}
	return
}

func (br *berReader) Read(dest []byte) (n int, err error) {
	n, err = br.Reader.Read(dest)
	br.bytesRead += n
	return
}

func base128IntLength(n int64) int {
	if n == 0 {
		return 1
	}

	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}

	return l
}

func appendBase128Int(dst []byte, n int64) []byte {
	l := base128IntLength(n)

	for i := l - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		dst = append(dst, o)
	}

	return dst
}

func encodeMeta(w io.Writer, class int, constructed bool, tag int, length int) (err error) {
	var dst []byte
	b := uint8(class) << 6
	if constructed {
		b |= 0x20
	}
	if tag >= 31 {
		b |= 0x1f
		dst = append(dst, b)
		dst = appendBase128Int(dst, int64(tag))
	} else {
		b |= uint8(tag)
		dst = append(dst, b)
	}
	if length >= 128 {
		l := lengthLength(length)
		dst = append(dst, 0x80|byte(l))
		for n := l; n > 0; n-- {
			dst = append(dst, byte(length>>uint((n-1)*8)))
		}
	} else {
		dst = append(dst, byte(length))
	}
	_, err = w.Write(dst)
	return
}

type continuation func(class int, constructed bool, tag int, length int) error

func (br *berReader) readBER(cont continuation) (err error) {
	b, err := br.ReadByte()
	if err != nil {
		return
	}
	class := int(b >> 6)
	constructed := b&0x20 != 0
	tag := int(b & 0x1f)
	if tag == 0x0f {
		tag = 0
		for {
			if b, err = br.ReadByte(); err != nil {
				return
			}
			tag += int(b & 0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	var length int
	switch b, err = br.ReadByte(); true {
	case err != nil:
		return
	case b == 0x80:
		length = -1 // indefinite
	case b < 0x80:
		length = int(b)
	default:
		for i := b & 0x7f; i > 0; i-- {
			if b, err = br.ReadByte(); err != nil {
				return
			}
			length = length*256 + int(b)
		}
	}
	return cont(class, constructed, tag, length)
}

type predicateError string

func (pe predicateError) Error() string {
	return string(pe)
}

func perr(f string, vs ...interface{}) error {
	return predicateError(fmt.Sprintf(f, vs...))
}

type predicate func(class int, constructed bool, tag int, length int) error

var errConditionNotMet = errors.New("optional condition not met")

func (br *berReader) optional(expected int, next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if expected == tag && length != 0 {
			return errors.WithMessage(br.readBER(next), fmt.Sprintf("optional[%d]", tag))
		}
		return errConditionNotMet
	}
}

func (br *berReader) tag(expected int) predicate {
	return func(class int, constructed bool, tag int, length int) error {
		if expected == tag {
			return nil
		}
		return errors.Wrap(perr("expected tag %d got %d", expected, tag), "tag")
	}
}

func (br *berReader) explicit(expected int, next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if expected != tag {
			return errors.Wrap(perr("expected explicit tag %d got %d", expected, tag), "explicit")
		}
		return errors.WithMessage(br.readBER(next), "explicit")
	}
}

func (br *berReader) object(dest interface{}, params string) continuation {
	return br.raw(-1, false, func(data []byte) (err error) {
		_, err = asn1.UnmarshalWithParams(data, dest, params)
		return errors.Wrap(err, "object")
	})
}

func (br *berReader) endOctets() continuation {
	return br.raw(0, false, func(data []byte) error {
		if !bytes.Equal(data, []byte{0, 0}) {
			return errors.Wrap(perr("expected end octets got %v", data), "endOctets")
		}
		return nil
	})
}

func (br *berReader) raw(expected int, optional bool, process func([]byte) error) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if length < 0 {
			return errors.Wrap(fmt.Errorf("tag %d is indefinite length", tag), "raw")
		}
		if expected > 0 && tag != expected {
			if !optional {
				return errors.Wrap(perr("expected tag %d got %d", expected, tag), "raw")
			}
			return errConditionNotMet
		}
		var buf bytes.Buffer
		if err = encodeMeta(&buf, class, constructed, tag, length); err != nil {
			return errors.Wrap(err, "raw")
		}
		if _, err = io.Copy(&buf, io.LimitReader(br, int64(length))); err != nil {
			return errors.Wrap(err, "raw")
		}
		return errors.Wrap(process(buf.Bytes()), "raw")
	}
}

func (br *berReader) octets(next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if tag != 4 {
			return errors.Wrap(perr("expected tag 4 got %d", tag), "octets")
		}
		if length < 0 {
			return errors.WithMessage(br.readBER(br.combine(next, br.endOctets())), "octets")
		}
		return errors.WithMessage(next(class, constructed, tag, length), "octets")
	}
}

func (br *berReader) oid(oid asn1.ObjectIdentifier, next continuation) continuation {
	return br.sequence(
		func(class int, constructed bool, tag int, length int) (err error) {
			var actual asn1.ObjectIdentifier
			if err = br.object(&actual, "")(class, constructed, tag, length); err != nil {
				return errors.WithMessage(err, "oid")
			}
			if !actual.Equal(oid) {
				return errors.Wrap(perr("expected oid %q got oid %q", oid, actual), "oid")
			}
			return nil
		}, next)
}

func (br *berReader) combine(conts ...continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		n := len(conts) - 1
		for i, cont := range conts {
			err = cont(class, constructed, tag, length)
			if errors.Cause(err) == errConditionNotMet {
				err = nil
				continue
			} else if err != nil || i == n {
				return
			}
			return br.readBER(br.combine(conts[i+1:]...))
		}
		return nil
	}
}

func (br *berReader) sequence(conts ...continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if length < 0 {
			conts = append(conts, br.endOctets())
		}
		if !constructed {
			return errors.Wrap(fmt.Errorf("expected constructed object, got tag %d", tag), "sequence")
		}
		return errors.WithMessage(br.readBER(br.combine(conts...)), "sequence")
	}
}

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
		_, err = io.Copy(dest, r)
		return errors.Wrap(err, "buildHashes")
	}
}

func (p7 *PKCS7) initHashes(class int, constructed bool, tag int, length int) (err error) {
	if err = p7.r.object(&p7.digestAlgorithmIdentifiers, "set")(class, constructed, tag, length); err != nil {
		return errors.Wrap(err, "initHashes")
	}
	p7.hashes = make(map[crypto.Hash]hash.Hash)
	for _, aid := range p7.digestAlgorithmIdentifiers {
		hash, err := getHashForOID(aid.Algorithm)
		if err != nil {
			return errors.Wrap(err, "initHashes: getHashForOID")
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
		return errors.Errorf("hash for signer %d not found", i)
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
		return errors.New("pkcs7: No certificate for signer")
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
	return errors.Errorf("unsupported signature algorithm: %v", algo)
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
					br.raw(0, true, func(data []byte) (err error) {
						certificates.Raw = data
						p7.Certificates, err = certificates.Parse()
						return
					}),
					br.raw(1, true, func(data []byte) (err error) {
						_, err = asn1.UnmarshalWithParams(data, &p7.CRLs, "optional,tag:1")
						return
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
