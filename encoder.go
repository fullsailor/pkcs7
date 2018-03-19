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

func (sd *SignedData) Sign(r io.Reader) (err error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	return nil
}
