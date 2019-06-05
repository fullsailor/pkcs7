package pkcs7

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"errors"
	"io"

	"golang.org/x/xerrors"
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
	if err != nil {
		return res, xerrors.Errorf("read from buffer: %w", err)
	}
	return res, nil
}

func (br *berReader) Read(dest []byte) (n int, err error) {
	n, err = br.Reader.Read(dest)
	br.bytesRead += n
	return
}

type continuation func(class int, constructed bool, tag int, length int) error

func (br *berReader) readBER(cont continuation) (rErr error) {
	b, err := br.ReadByte()
	if err != nil {
		return err
	}
	class := int(b >> 6)
	constructed := b&0x20 != 0
	tag := int(b & 0x1f)
	if tag == 0x0f {
		tag = 0
		for {
			if b, err = br.ReadByte(); err != nil {
				return err
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
		return err
	case b == 0x80:
		length = -1 // indefinite
	case b < 0x80:
		length = int(b)
	default:
		for i := b & 0x7f; i > 0; i-- {
			if b, err = br.ReadByte(); err != nil {
				return err
			}
			length = length*256 + int(b)
		}
	}
	return cont(class, constructed, tag, length)
}

type predicate func(class int, constructed bool, tag int, length int) error

var errConditionNotMet = errors.New("optional condition not met")

func (br *berReader) optional(expected int, next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if expected == tag && length != 0 {
			if err := br._sequence(next)(class, constructed, tag, length); err != nil {
				return xerrors.Errorf("optional[%d]: %w", tag, err)
			}
			return nil
		}
		return errConditionNotMet
	}
}

func (br *berReader) _repeat(next continuation) error {
	for {
		err := br.readBER(next)
		if xerrors.Is(err, errConditionNotMet) {
			return nil
		} else if err != nil {
			return err
		}
	}
}

func (br *berReader) tag(expected int) predicate {
	return func(class int, constructed bool, tag int, length int) error {
		if err := br._tag(expected)(class, constructed, tag, length); err != nil {
			return xerrors.Errorf("tag: %w", err)
		}
		return nil
	}
}

func (br *berReader) _tag(expected int) predicate {
	return func(class int, constructed bool, tag int, length int) error {
		if expected == tag {
			return nil
		}
		return xerrors.Errorf("expected tag %d got %d", expected, tag)
	}
}

func (br *berReader) explicit(expected int, next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if expected != tag {
			return xerrors.Errorf("explicit: expected explicit tag %d got %d", expected, tag)
		}
		if err := br.readBER(next); err != nil {
			return xerrors.Errorf("explicit: %w", err)
		}
		return nil
	}
}

func (br *berReader) object(dest interface{}, params string) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if err := br._object(dest, params)(class, constructed, tag, length); err != nil {
			return xerrors.Errorf("object: %w", err)
		}
		return nil
	}
}

func (br *berReader) _object(dest interface{}, params string) continuation {
	return br._raw(-1, false, func(data []byte) (err error) {
		if _, err = asn1.UnmarshalWithParams(data, dest, params); err != nil {
			return xerrors.Errorf("unmarshalWithParams: %w", err)
		}
		return nil
	})
}

func (br *berReader) endOctets() continuation {
	return br._raw(0, false, func(data []byte) error {
		if !bytes.Equal(data, []byte{0, 0}) {
			return xerrors.Errorf("endOctets: expected end octets got %v", data)
		}
		return nil
	})
}

func (br *berReader) readTillEnd(dest io.Writer) (err error) {
	var stop bool
	for !stop {
		if err := br.readBER(br._raw(-1, true, func(data []byte) error {
			if bytes.Equal(data, []byte{0, 0}) {
				stop = true
				return nil
			}
			if _, err = dest.Write(data); err != nil {
				return xerrors.Errorf("writing to inner buffer: %w", err)
			}
			return nil
		})); err != nil {
			return err
		}
	}
	return nil
}

func (br *berReader) raw(expected int, optional bool, process func([]byte) error) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if err := br._raw(expected, optional, process)(class, constructed, tag, length); err != nil {
			return xerrors.Errorf("raw: %w", err)
		}
		return nil
	}
}

func (br *berReader) _raw(expected int, optional bool, process func([]byte) error) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if expected >= 0 && tag != expected {
			if !optional {
				return xerrors.Errorf("expected tag %d got %d", expected, tag)
			}
			return errConditionNotMet
		}
		var buf bytes.Buffer
		if length < 0 {
			if !constructed {
				return xerrors.Errorf("tag %d is indefinite length", tag)
			} else if err = br.readTillEnd(&buf); err != nil {
				return err
			}
		} else {
			if _, err = buf.Write(encodeMeta(class, constructed, tag, length)); err != nil {
				return err
			}
			if _, err = io.Copy(&buf, io.LimitReader(br, int64(length))); err != nil {
				return err
			}
		}
		if err := process(buf.Bytes()); err != nil {
			return xerrors.Errorf("process: %w", err)
		}
		return nil
	}
}

func (br *berReader) octets(next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if err := br._octets(next)(class, constructed, tag, length); err != nil {
			return xerrors.Errorf("octets: %w", err)
		}
		return nil
	}
}

func (br *berReader) _octets(next continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		switch tag {
		case 0:
			if length == 0 {
				return errConditionNotMet
			}
			return xerrors.Errorf("unexpected object of length %d", length)
		case 4:
			if length < 0 {
				return br._repeat(br._octets(next))
			}
			return next(class, constructed, tag, length)
		}
		return xerrors.Errorf("expected tag 4 got %d: %w", tag)
	}
}

func (br *berReader) oid(oid asn1.ObjectIdentifier, next continuation) continuation {
	return br._sequence(
		func(class int, constructed bool, tag int, length int) (err error) {
			var actual asn1.ObjectIdentifier
			if err = br._object(&actual, "")(class, constructed, tag, length); err != nil {
				return xerrors.Errorf("oid: %w", err)
			}
			if !actual.Equal(oid) {
				return xerrors.Errorf("oid: expected oid %q got oid %q", oid, actual)
			}
			return nil
		}, next)
}

func (br *berReader) combine(conts ...continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		n := len(conts) - 1
		for i, cont := range conts {
			err = cont(class, constructed, tag, length)
			if xerrors.Is(err, errConditionNotMet) {
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
		if err := br._sequence(conts...)(class, constructed, tag, length); err != nil {
			return xerrors.Errorf("sequence: %w", err)
		}
		return nil
	}
}

func (br *berReader) _sequence(conts ...continuation) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		if length < 0 {
			conts = append(conts, br.endOctets())
		}
		if !constructed {
			return xerrors.Errorf("expected constructed object, got tag %d", tag)
		}
		if err := br.readBER(br.combine(conts...)); err != nil {
			return err
		}
		return nil
	}
}
