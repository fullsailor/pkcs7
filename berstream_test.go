package pkcs7

import (
	"bytes"
	"io"
	"testing"
)

func dump(t *testing.T, indent int, r io.Reader) error {
	idt := ""
	for i := 0; i < indent; i++ {
		idt += ">"
	}
	err := readBER(r, func(class int, constructed bool, tag int, length int, rest io.Reader) (err error) {
		t.Logf("%sclass=%d constructed=%t tag=%d len=%d", idt, class, constructed, tag, length)
		if length > 0 && !constructed {
			b := make([]byte, length)
			if _, err = r.Read(b); err != nil {
				return nil
			}
			t.Logf("%sdata(%d): %v", idt, len(b), b)
			return nil
		}
		for {
			switch err = dump(t, indent+1, rest); err {
			case io.EOF:
				return nil
			case nil:
				break
			default:
				return
			}
		}
	})
	if err != nil && err != io.EOF {
		t.Errorf("%s%+v", idt, err)
	}
	return err
}

func TestReadBER(t *testing.T) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	r := bytes.NewReader(fixture.Input)
	dump(t, 0, r)
}
