package pkcs7

import (
	"errors"
	"io"
	"os"
)

// NewEncoder creates stream PKCS signer
func NewEncoder(w io.Writer) *SignedData {
	return &SignedData{
		w: w,
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
	var size int64
	switch t := r.(type) {
	case *os.File:
		stat, err := t.Stat()
		if err != nil {
			return err
		}
		size = stat.Size()
	case Buffer:
		size = int64(t.Len())
	default:
		return errors.New("provided reader has no way to specify size")
	}

}
