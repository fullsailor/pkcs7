package pkcs7

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
)

func dump(r io.Reader, tag, length int) (next visitFunc, err error) {
	next = dump
	data := make([]byte, length)
	if _, err = r.Read(data); err != nil {
		return
	}
	fmt.Println(tag, length, data)
	return
}

func TestReadBER(t *testing.T) {
	for _, fixture := range []string{SignedTestFixture, EC2IdentityDocumentFixture, AppStoreRecieptFixture} {
		fixture := UnmarshalTestFixture(fixture)
		p7 := NewDecoder(bytes.NewReader(fixture.Input))
		if err := p7.verify(ioutil.Discard); err != nil {
			t.Errorf("%+v", err)
		}
	}
}
