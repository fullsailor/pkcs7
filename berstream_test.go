package pkcs7

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestReadBER(t *testing.T) {
	for _, fixture := range []string{SignedTestFixture, EC2IdentityDocumentFixture, AppStoreRecieptFixture} {
		fixture := UnmarshalTestFixture(fixture)
		p7 := NewDecoder(bytes.NewReader(fixture.Input))
		Parse(fixture.Input)
		if err := p7.verify(ioutil.Discard); err != nil {
			t.Errorf("%v", err)
		}
	}
}
