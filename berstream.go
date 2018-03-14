package pkcs7

import (
	"bufio"
	"encoding/asn1"
	"errors"
	"fmt"
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

type visitFunc func(r io.Reader, tag, length int) (next visitFunc, err error)

var errContentEnd = errors.New("end of contents")

func (br *berReader) walk(visit visitFunc) (n int, next visitFunc, err error) {
	next = visit
	err = br.readBER(func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if tag == 0 && length == 0 {
			return errContentEnd
		}
		if !constructed {
			if length == -1 {
				return errors.New("indefinite length object must be constructed")
			}
			n = length
			next, err = visit(br, tag, length)
			return
		}
		var nn int
	loop:
		for n < length || length == -1 {
			br := &berReader{Reader: br.Reader}
			nn, next, err = br.walk(next)
			n += br.bytesRead
			switch {
			case err == errContentEnd:
				err = nil
				break loop
			case next == nil:
				return
			case err == nil:
				break
			default:
				return
			}
			n += nn
		}
		return
	})
	return
}

func (br *berReader) explicit(optional bool, expected int, trueCont, falseCont continuation) continuation {
	return func(class int, constructed bool, tag int, length int, rest io.Reader) error {
		if tag == expected {
			return br.readBER(trueCont)
		}
		if !optional {
			return fmt.Errorf("unexpected tag: %d", tag)
		}
		return falseCont(class, constructed, tag, length, rest)
	}
}

func (br *berReader) oid(expected asn1.ObjectIdentifier, trueCont, falseCont continuation) continuation {
	return func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if tag != 6 {
			return fmt.Errorf("unexpected tag: %d", tag)
		}
		if length > 127 {
			return fmt.Errorf("OID bytes too long: %d", length)
		}
		data := make([]byte, length+2)
		if _, err = rest.Read(data[2:]); err != nil {
			return
		}
		data[0] = 6
		data[1] = byte(length)
		var id asn1.ObjectIdentifier
		if _, err = asn1.Unmarshal(data, &id); err != nil {
			return
		}
		if id.Equal(expected) {
			return br.readBER(trueCont)
		}
		return br.readBER(falseCont)
	}
}
