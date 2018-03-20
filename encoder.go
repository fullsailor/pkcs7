package pkcs7

import (
	"crypto"
	"hash"
	"io"
	"time"
)

// NewEncoder creates stream PKCS signer
func NewEncoder(w io.Writer) *SignedData {
	res := &SignedData{
		w: &berWriter{w},
	}
	res.sd.ContentInfo.ContentType = oidSignedData
	return res
}

func (sd *SignedData) sign(r io.Reader, size int) continuation {
	return sd.w.explicit(4, size, func(class int, constructed bool, _ int, _ int) (err error) {
		r = io.LimitReader(r, int64(size))
		if _, err = io.Copy(sd.w, r); err != nil {
			return
		}
		for i, si := range sd.sd.SignerInfos {
			hash, err := getHashForOID(si.DigestAlgorithm.Algorithm)
			if err != nil {
				return err
			}
			messageDigest := sd.hashes[hash].Sum(nil)
			attrs := &attributes{}
			attrs.Add(oidAttributeContentType, sd.sd.ContentInfo.ContentType)
			attrs.Add(oidAttributeMessageDigest, messageDigest)
			attrs.Add(oidAttributeSigningTime, time.Now())
			finalAttrs, err := attrs.ForMarshaling()
			if err != nil {
				return err
			}
			signature, err := signAttributes(finalAttrs, sd.pkeys[i], crypto.SHA256)
			if err != nil {
				return err
			}
			sd.sd.SignerInfos[i].AuthenticatedAttributes = finalAttrs
			sd.sd.SignerInfos[i].EncryptedDigest = signature
		}
		return
	})
}

func (sd *SignedData) initHashes(r io.Reader) (io.Reader, error) {
	sd.hashes = make(map[crypto.Hash]hash.Hash)
	for _, si := range sd.sd.SignerInfos {
		hash, err := getHashForOID(si.DigestAlgorithm.Algorithm)
		if err != nil {
			return r, err
		}
		if sd.hashes[hash] == nil {
			h := hash.New()
			sd.hashes[hash] = h
			r = io.TeeReader(r, h)
			sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers, si.DigestAlgorithm)
		}
	}
	return r, nil
}

func (sd *SignedData) SignFrom(r io.Reader, size int) (err error) {
	version := 1
	w := sd.w
	sd.sd.Certificates = marshalCertificates(sd.certs)
	if r, err = sd.initHashes(r); err != nil {
		return nil
	}
	return w.writeBER(
		w.oid(oidSignedData,
			w.optional(0,
				w.sequence(
					w.object(version, ""),
					w.object(sd.sd.DigestAlgorithmIdentifiers, "set"),
					w.oid(
						oidData,
						w.optional(0,
							sd.sign(r, size),
						),
					),
					w.raw(0, sd.sd.Certificates.Raw),
					w.object(sd.sd.CRLs, "optional,tag:1"),
					w.object(sd.sd.SignerInfos, "set"),
				),
			),
		),
	)
}
