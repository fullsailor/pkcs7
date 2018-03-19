package pkcs7

import (
	"errors"
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

func (w *berWriter) signdata(r io.Reader) continuation {
	size := -1
	var err error
	switch t := r.(type) {
	case *os.File:
		stat, err := t.Stat()
		if err == nil {
			size = int(stat.Size())
		}
	case Buffer:
		size = t.Len()
	}
	return w.explicit(4, size, func(class int, constructed bool, _ int, _ int) error {
		if err != nil {
			return err
		} else if size == -1 {
			return errors.New("specified reader does not provide size")
		}
		_, err = io.Copy(w, io.LimitReader(r, int64(size)))
		return err
	})
}

func (sd *SignedData) SignTo(r io.Reader) (err error) {
	version := 1
	sd.sd.Certificates = marshalCertificates(sd.certs)
	for _, si := range sd.sd.SignerInfos {
		sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers, si.DigestAlgorithm)
	}
	w := sd.w
	return w.writeBER(
		w.oid(oidSignedData,
			w.optional(0,
				w.sequence(
					w.object(&version, ""),
					w.object(&sd.sd.DigestAlgorithmIdentifiers, "set"),
					w.oid(
						oidData,
						w.optional(0,
							w.octets(w.signdata(r)),
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
