package pkcs7

import (
	"bytes"
	"fmt"
	"io"
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
		br := newBerReader(bytes.NewReader(fixture.Input))
		fmt.Println("*************", fixture.Input)
		if _, _, err := br.walk(dump); err != nil {
			t.Fatal(err)
		}
	}
}
