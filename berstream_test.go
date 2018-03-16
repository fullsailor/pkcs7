package pkcs7

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestReadBER(t *testing.T) {
	for i, fixture := range []string{SignedTestFixture, AppStoreRecieptFixture} {
		fixture := UnmarshalTestFixture(fixture)
		p7 := NewDecoder(bytes.NewReader(fixture.Input))
		if err := p7.VerifyTo(ioutil.Discard); err != nil {
			t.Errorf("%+v", err)
			continue
		}
		t.Log(i, "ok")
	}
}

func BenchmarkVerify(b *testing.B) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := NewDecoder(bytes.NewBuffer(fixture.Input)).VerifyTo(ioutil.Discard); err != nil {
			b.Errorf("Verify failed with error: %v", err)
		}
	}
}
