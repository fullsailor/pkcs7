package pkcs7

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestReadBER(t *testing.T) {
	for i, fixture := range []string{SignedTestFixture, EC2IdentityDocumentFixture, AppStoreRecieptFixture} {
		fmt.Println("#######", i)
		fixture := UnmarshalTestFixture(fixture)
		p7 := NewDecoder(bytes.NewReader(fixture.Input))
		ioutil.WriteFile(fmt.Sprintf("%d.der", i), fixture.Input, 0664)
		Parse(fixture.Input)
		if err := p7.verify(ioutil.Discard); err != nil {
			t.Errorf("%v", err)
		}
	}
}
