package pkcs7

import (
	"bufio"
	"io"
)

func readBER(r io.Reader, cont func(class int, constructed bool, tag int, length int, rest io.Reader) error) (err error) {
	buf := bufio.NewReader(r)
	b, err := buf.ReadByte()
	if err != nil {
		return
	}
	class := int(b >> 6)
	constructed := b&0x20 != 0
	tag := int(b & 0x1F)
	if tag == 0x0f {
		tag = 0
		for {
			if b, err = buf.ReadByte(); err != nil {
				return
			}
			tag += int(b & 0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	var length int
	switch b, err = buf.ReadByte(); true {
	case err != nil:
		return
	case b == 0x80:
		length = -1 // indefinite
	case b < 0x80:
		length = int(b)
	default:
		for i := b & 0x7f; i > 0; i-- {
			if b, err = buf.ReadByte(); err != nil {
				return
			}
			length = length*256 + int(b)
		}
	}
	return cont(class, constructed, tag, length, buf)
}
