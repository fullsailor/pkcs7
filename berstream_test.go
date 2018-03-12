package pkcs7

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestReadBER(t *testing.T) {
	dump := func(tags ...int) visitFunc {
		return func(r io.Reader, length int) (n int, err error) {
			data := make([]byte, length)
			if n, err = r.Read(data); err != nil {
				return
			}
			fmt.Println(tags, length, data)
			return
		}
	}
	for _, fixture := range []string{SignedTestFixture, EC2IdentityDocumentFixture, AppStoreRecieptFixture} {
		fixture := UnmarshalTestFixture(fixture)
		br := newBerReader(bytes.NewReader(fixture.Input))
		fmt.Println("***", fixture.Input)
		if _, err := br.walk(dump); err != nil {
			t.Fatal(err)
		}
	}
}
