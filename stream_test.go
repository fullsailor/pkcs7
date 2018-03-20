package pkcs7

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"reflect"
	"testing"
)

func TestDecoder_VerifyTo(t *testing.T) {
	for _, fixture := range []string{SignedTestFixture, AppStoreRecieptFixture} {
		buf := new(bytes.Buffer)
		fixture := UnmarshalTestFixture(fixture)
		p7 := NewDecoder(bytes.NewReader(fixture.Input))
		if err := p7.VerifyTo(buf); err != nil {
			t.Errorf("%+v", err)
			continue
		}
		p7a, err := Parse(fixture.Input)
		if err != nil {
			t.Errorf("%+v", err)
			continue
		}
		if err = p7a.Verify(); err != nil {
			t.Errorf("%+v", err)
			continue
		}
		if !bytes.Equal(p7a.Content, buf.Bytes()) {
			t.Error("content does not match")
		}
		if !reflect.DeepEqual(p7a.Signers, p7.Signers) {
			t.Error("signer info parsed incorrectly")
		}
		if !reflect.DeepEqual(p7a.Certificates, p7.Certificates) {
			t.Error("certificates parsed incorrectly")
		}
		if !reflect.DeepEqual(p7a.CRLs, p7.CRLs) {
			t.Error("CRLs parsed incorrectly")
		}
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
	content := make([]byte, 10000)
	if _, err = rand.Read(content); err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	toBeSigned := NewEncoder(buf)
	if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("%+v", err)
	}
	if err = toBeSigned.SignFrom(bytes.NewReader(content), len(content)); err != nil {
		t.Fatalf("%+v", err)
	}
	p7a, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("%+v", err)
	} else if err = p7a.Verify(); err != nil {
		t.Fatalf("%+v", err)
	}
	if !bytes.Equal(content, p7a.Content) {
		t.Fatal("content does not match")
	}
	p7 := NewDecoder(buf)
	dest := new(bytes.Buffer)
	if err := p7.VerifyTo(dest); err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(content, dest.Bytes()) {
		t.Fatal("content does not match")
	}
}

var content = bytes.NewReader(make([]byte, 128*1024*1024))

func BenchmarkSignFrom(b *testing.B) {
	cert, err := createTestCertificate()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		toBeSigned := NewEncoder(ioutil.Discard)
		if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
			b.Fatalf("Cannot add signer: %s", err)
		}
		if err = toBeSigned.SignFrom(content, int(content.Size())); err != nil {
			b.Fatalf("Cannot finish signing data: %s", err)
		}
		content.Seek(0, 0)
	}
}
