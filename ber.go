package pkcs7

import (
	"bytes"
	"errors"
	"io"
)

type asn1Object interface {
	EncodeTo(w io.Writer) error
	Len() int
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) Len() (res int) {
	for _, obj := range s.content {
		res += obj.Len()
	}
	return
}

func (s asn1Structured) EncodeTo(out io.Writer) (err error) {
	//fmt.Printf("%s--> tag: % X\n", strings.Repeat("| ", encodeIndent), s.tagBytes)
	if _, err = out.Write(s.tagBytes); err != nil {
		return
	}
	if err = encodeLength(out, s.Len()); err != nil {
		return
	}
	for _, obj := range s.content {
		err = obj.EncodeTo(out)
		if err != nil {
			return err
		}
	}
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) EncodeTo(out io.Writer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.Len()); err != nil {
		return err
	}
	out.Write(p.content)

	return nil
}

func (p asn1Primitive) Len() int {
	return p.length
}

func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	//fmt.Printf("--> ber2der: Transcoding %d bytes\n", len(ber))
	out := new(bytes.Buffer)

	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}
	obj.EncodeTo(out)

	// if offset < len(ber) {
	//	return nil, fmt.Errorf("ber2der: Content longer than expected. Got %d, expected %d", offset, len(ber))
	//}

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out io.Writer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		_, err = out.Write([]byte{byte(i >> uint((n-1)*8))})
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//  length | byte 1 | bytes n
//  0      | 0x00   | -
//  120    | 0x78   | -
//  200    | 0x81   | 0xC8
//  500    | 0x82   | 0x01 0xF4
//
func encodeLength(out io.Writer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		_, err = out.Write([]byte{0x80 | byte(l)})
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		_, err = out.Write([]byte{byte(length)})
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset int) (asn1Object, int, error) {
	//fmt.Printf("\n====> Starting readObject at offset: %d\n\n", offset)
	tagStart := offset
	b := ber[offset]
	offset++
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
		}
		tag = tag*128 + ber[offset] - 0x80
		offset++
	}
	tagEnd := offset

	kind := b & 0x20
	/*
		if kind == 0 {
			fmt.Print("--> Primitive\n")
		} else {
			fmt.Print("--> Constructed\n")
		}
	*/
	// read length
	var length int
	l := ber[offset]
	offset++
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if 0x0 == (int)(ber[offset]) {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		//fmt.Printf("--> (compute length) indicator byte: %x\n", l)
		//fmt.Printf("--> (compute length) length bytes: % X\n", ber[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}

	//fmt.Printf("--> length        : %d\n", length)
	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, errors.New("ber2der: BER tag length is more than available data")
	}
	//fmt.Printf("--> content start : %d\n", offset)
	//fmt.Printf("--> content end   : %d\n", contentEnd)
	//fmt.Printf("--> content       : % X\n", ber[offset:contentEnd])
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)

			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}

				if terminated {
					break
				}
			}
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, errors.New("ber2der: Invalid BER format")
	}

	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}
