package pkcs7

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"regexp"
)

type berReader struct {
	*bufio.Reader
	bytesRead int
}

var nameRe = regexp.MustCompile(`((\w+)(\.\w+)?\)?)([-][^-]*)?$`)

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
			dst = append(dst, byte(l>>uint((n-1)*8)))
		}
	} else {
		dst = append(dst, byte(length))
	}
	_, err = w.Write(dst)
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

type predicate func(class int, constructed bool, tag int, length int) error

var errFalse = errors.New("condition not met")

func (br *berReader) cond(p predicate, trueCont, falseCont continuation) continuation {
	return func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if err = p(class, constructed, tag, length); err == errFalse {
			return falseCont(class, constructed, tag, length, rest)
		} else if err != nil {
			return
		}
		return trueCont(class, constructed, tag, length, rest)
	}
}

func (br *berReader) tag(expected int, optional bool) predicate {
	return func(class int, constructed bool, tag int, length int) error {
		if expected == tag {
			return nil
		}
		if !optional {
			return fmt.Errorf("expected tag %d got %d", expected, tag)
		}
		return errFalse
	}
}

func (br *berReader) explicit(p predicate, next continuation) continuation {
	return func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if err = p(class, constructed, tag, length); err == errFalse {
			return nil
		} else if err != nil {
			return
		}
		return br.readBER(next)
	}
}

func (br *berReader) parseASN1(dest interface{}, params string) continuation {
	return func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if length < 0 {
			return fmt.Errorf("tag %d is indefinite length", tag)
		}
		var buf bytes.Buffer
		if err = encodeMeta(&buf, class, constructed, tag, length); err != nil {
			return
		}
		if _, err = io.Copy(&buf, io.LimitReader(rest, int64(length))); err != nil {
			return
		}
		_, err = asn1.UnmarshalWithParams(buf.Bytes(), dest, params)
		return
	}
}

func (br *berReader) oid(oid asn1.ObjectIdentifier, optional bool) predicate {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if tag != 6 {
			return fmt.Errorf("expected oid %s got tag %d", oid, tag)
		}
		var actual asn1.ObjectIdentifier
		if err = br.readBER(br.parseASN1(&actual, "")); err != nil {
			return
		}
		if !actual.Equal(oid) {
			if !optional {
				return fmt.Errorf("expected oid %q got oid %q", oid, actual)
			}
			return errFalse
		}
		return nil
	}
}

func (br *berReader) sequence(conts ...continuation) continuation {
	return func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		if !constructed {
			return fmt.Errorf("expected constructed object, got tag %d", tag)
		}
		for _, cont := range conts {
			if err = br.readBER(cont); err != nil {
				break
			}
		}
		return
	}
}

func NewDecoder(r io.Reader) *PKCS7 {
	return &PKCS7{
		r: newBerReader(r),
	}
}

func (p7 *PKCS7) verify(dest io.Writer) error {
	br := p7.r
	var ci contentInfo
	err := br.readBER(
		br.sequence(
			br.cond(
				br.oid(oidSignedData, true),
				br.sequence(
					br.parseASN1(&ci, "explicit,optional,tag:0"),
				),
				nil,
			),
		),
	)
	fmt.Println(ci, err)
	return err
}
