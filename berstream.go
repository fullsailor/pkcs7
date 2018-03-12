package pkcs7

import (
	"bufio"
	"errors"
	"io"
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

type continuation func(class int, constructed bool, tag int, length int, rest io.Reader) error

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
	return cont(class, constructed, tag, length, newBerReader(br.Reader))
}

type visitFunc func(r io.Reader, length int) (int, error)

type visitFuncFactory func(tags ...int) visitFunc

var errContentEnd = errors.New("end of contents")

func (br *berReader) walk(vff visitFuncFactory, path ...int) (n int, err error) {
	err = br.readBER(func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if tag == 0 && length == 0 {
			return errContentEnd
		}
		tags := make([]int, len(path)+1)
		copy(tags, path)
		tags[len(tags)-1] = tag
		visit := vff(tags...)
		if !constructed {
			if length == -1 {
				return errors.New("indefinite length object must be constructed")
			}
			n, err = visit(br, length)
			return
		}
		var nn int
	loop:
		for n < length || length == -1 {
			br := &berReader{Reader: br.Reader}
			nn, err = br.walk(vff, tags...)
			switch err {
			case errContentEnd:
				err = nil
				break loop
			case nil:
				break
			default:
				return
			}
			n += nn + br.bytesRead
		}
		return
	})
	return
}

// NewDecoder returns new unparsed CMS struct
func NewDecoder(r io.Reader) *PKCS7 {
	return &PKCS7{r: newBerReader(r)}
}
