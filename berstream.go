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

type visitFunc func(r io.Reader, tag, length int) (next visitFunc, err error)

var errContentEnd = errors.New("end of contents")

func (br *berReader) walk(visit visitFunc) (n int, next visitFunc, err error) {
	next = visit
	err = br.readBER(func(class int, constructed bool, tag int, length int) (err error) {
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

type predicateError string

func (pe predicateError) Error() string {
	return string(pe)
}

func perr(f string, vs ...interface{}) error {
	return predicateError(fmt.Sprintf(f, vs...))
}

type predicate func(class int, constructed bool, tag int, length int) error

func (br *berReader) optional(next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		err = next(class, constructed, tag, length)
		if _, ok := err.(predicateError); ok {
			return nil
		}
		return
	}
}

func (br *berReader) branch(p predicate, trueCont continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if err = p(class, constructed, tag, length); err != nil {
			return
		}
		return trueCont(class, constructed, tag, length)
	}
}

func (br *berReader) tag(expected int) predicate {
	return func(class int, constructed bool, tag int, length int) error {
		if expected == tag {
			return nil
		}
		return perr("expected tag %d got %d", expected, tag)
	}
}

func (br *berReader) explicit(expected int, next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if expected != tag {
			return perr("expected explicit tag %d got %d", expected, tag)
		}
		return br.readBER(next)
	}
}

func (br *berReader) object(dest interface{}, params string) continuation {
	return br.raw(func(data []byte) (err error) {
		_, err = asn1.UnmarshalWithParams(data, dest, params)
		return
	})
}

func (br *berReader) raw(process func([]byte) error) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if length < 0 {
			return fmt.Errorf("tag %d is indefinite length", tag)
		}
		var buf bytes.Buffer
		if err = encodeMeta(&buf, class, constructed, tag, length); err != nil {
			return
		}
		if _, err = io.Copy(&buf, io.LimitReader(br, int64(length))); err != nil {
			return
		}
		return process(buf.Bytes())
	}
}

func (br *berReader) oid(oid asn1.ObjectIdentifier, next continuation) continuation {
	return br.sequence(
		func(class int, constructed bool, tag int, length int) (err error) {
			if tag != 6 {
				return perr("expected oid %s got tag %d", oid, tag)
			}
			var actual asn1.ObjectIdentifier
			if err = br.object(&actual, "")(class, constructed, tag, length); err != nil {
				return
			}
			if !actual.Equal(oid) {
				return perr("expected oid %q got oid %q", oid, actual)
			}
			return nil
		}, next)
}

func (br *berReader) sequence(conts ...continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if !constructed {
			return fmt.Errorf("expected constructed object, got tag %d", tag)
		}
		for _, cont := range conts {
			if err = br.readBER(cont); err != nil {
				return
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
	var si signedData
	var data []byte
	err := br.readBER(
		br.oid(oidSignedData,
			br.explicit(0,
				br.sequence(
					br.object(&si.Version, ""),
					br.object(&si.DigestAlgorithmIdentifiers, "set"),
					br.sequence(
						br.object(&si.ContentInfo.ContentType, ""),
						br.optional(
							br.explicit(0,
								br.raw(func(data []byte) (err error) {
									return nil
								}),
							),
						),
					),
					br.explicit(0,
						//                         func(class int, constructed bool, tag int, length int) (err error) {
						//                             fmt.Println("tag:", tag, length, constructed, class)
						//                             return nil
						//                         },
						br.raw(func(data []byte) (err error) {
							fmt.Println(data)
							return
						}),
					),
				),
			),
		),
	)
	fmt.Println(si, data, err)
	return err
}
