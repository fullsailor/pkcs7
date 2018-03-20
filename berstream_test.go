package pkcs7

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestDecoder_VerifyTo(t *testing.T) {
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

func BenchmarkVerifyTo(b *testing.B) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := NewDecoder(bytes.NewBuffer(fixture.Input)).VerifyTo(ioutil.Discard); err != nil {
			b.Errorf("Verify failed with error: %v", err)
		}
	}
}

func TestEncoder_SignTo(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	buf := new(bytes.Buffer)
	toBeSigned := NewEncoder(buf)
	if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("%+v", err)
	}
	if err = toBeSigned.SignFrom(bytes.NewReader(content), len(content)); err != nil {
		t.Fatalf("%+v", err)
	}
	ioutil.WriteFile("test.der", buf.Bytes(), 0664)
	p7 := NewDecoder(buf)
	dest := new(bytes.Buffer)
	if err := p7.VerifyTo(dest); err != nil {
		t.Logf("%+v", p7)
		t.Logf("%q", string(dest.Bytes()))
		t.Errorf("%v", err)
	}
}
