package pkcs7

import (
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

type berWriter struct {
	io.Writer
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
	switch {
	case length >= 128:
		l := lengthLength(length)
		dst = append(dst, 0x80|byte(l))
		for n := l; n > 0; n-- {
			dst = append(dst, byte(length>>uint((n-1)*8)))
		}
	case length < 0:
		dst = append(dst, 0x80)
	default:
		dst = append(dst, byte(length))
	}
	_, err = w.Write(dst)
	err = errors.Wrap(err, "writing meta")
	return
}

func (w *berWriter) object(val interface{}, params string) continuation {
	return func(class int, constructed bool, tag int, length int) (err error) {
		data, err := asn1.MarshalWithParams(val, params)
		if err != nil {
			return errors.Wrap(err, "marshaling asn1")
		}
		_, err = w.Write(data)
		err = errors.Wrap(err, "writing data bytes")
		return
	}
}

func (w *berWriter) oid(oid asn1.ObjectIdentifier, next continuation) continuation {
	return w.sequence(w.object(oid, ""), next)
}

func (w *berWriter) class(class int, next continuation) continuation {
	return func(_ int, constructed bool, tag int, length int) (err error) {
		return next(class, constructed, tag, length)
	}
}

func (w *berWriter) constructed(next continuation) continuation {
	return func(class int, _ bool, tag int, length int) (err error) {
		return next(class, true, tag, length)
	}
}

func (w *berWriter) explicit(tag int, length int, next continuation) continuation {
	return func(class int, constructed bool, _ int, _ int) (err error) {
		if err = encodeMeta(w, class, constructed, tag, length); err != nil {
			return
		}
		if err = next(0, false, 0, 0); err != nil {
			return
		}
		if length < 0 {
			_, err = w.Write([]byte{0, 0})
			return
		}
		return
	}
}

func (w *berWriter) optional(tag int, next continuation) continuation {
	return w.class(2, w.constructed(w.explicit(tag, -1, next)))
}

func (w *berWriter) raw(tag int, data []byte) continuation {
	return func(class int, constructed bool, _ int, _ int) (err error) {
		fmt.Println("***", tag, data[:10], len(data))
		if err = encodeMeta(w, class, constructed, tag, len(data)); err != nil {
			return
		}
		_, err = w.Write(data)
		err = errors.Wrap(err, "writing raw bytes")
		return
	}
}

func (w *berWriter) sequence(seq ...continuation) continuation {
	return w.constructed(
		w.explicit(16, -1,
			func(class int, constructed bool, tag int, length int) (err error) {
				for _, cont := range seq {
					if err = cont(class, constructed, tag, length); err != nil {
						break
					}
				}
				return
			},
		),
	)
}

func (w *berWriter) octets(next continuation) continuation {
	return w.constructed(w.explicit(4, -1, next))
}

func (w *berWriter) writeBER(cont continuation) error {
	return cont(0, false, 0, 0)
}
