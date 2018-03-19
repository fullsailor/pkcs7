package pkcs7

import (
	"crypto"
	"errors"
	"hash"
	"io"
	"os"
)

// NewEncoder creates stream PKCS signer
func NewEncoder(w io.Writer) *SignedData {
	return &SignedData{
		w: &berWriter{w},
	}
}

// Buffer adds size to io.Reader
type Buffer interface {
	io.Reader
	Len() int
}

type buf struct {
	io.Reader
	size int
}

func (rs buf) Len() int {
	return rs.size
}

// WithSize creates io.Reader that has size information
func WithSize(r io.Reader, size int) Buffer {
	return buf{Reader: r, size: size}
}

func (w *berWriter) signData(r io.Reader) continuation {
	return w.explicit(4, 0, func(class int, constructed bool, _ int, _ int) (err error) {
		_, err = io.Copy(w, r)
		return err
	})
}

func (sd *SignedData) initHashes(r io.Reader) (io.Reader, error) {
	size := -1
	switch t := r.(type) {
	case *os.File:
		stat, err := t.Stat()
		if err == nil {
			size = int(stat.Size())
		}
	case Buffer:
		size = t.Len()
	default:
		return r, errors.New("specified reader does not provide size")
	}
	r = io.LimitReader(r, int64(size))
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

func (sd *SignedData) SignTo(r io.Reader) (err error) {
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
					w.object(&version, ""),
					w.object(&sd.sd.DigestAlgorithmIdentifiers, "set"),
					w.oid(
						oidData,
						w.optional(0,
							w.octets(w.signData(r)),
						),
					),
					w.raw(sd.sd.Certificates.Raw),
					w.object(&sd.sd.CRLs, "optional,tag:1"),
					w.object(&sd.sd.SignerInfos, "set"),
				),
			),
		),
	)
}
