package pkcs7

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestParse(t *testing.T) {
	example1, _ := ioutil.ReadFile("test_example.p7")
	p7, err := Parse(example1)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	fmt.Printf("p7 Content: %q\n", p7.Content)
	fmt.Printf("p7 Certificates:\n")
	for idx, cert := range p7.Certificates {
		fmt.Printf("   [%d] %s\n", idx, cert.Subject.CommonName)
		fmt.Printf("        %#v\n", cert.PublicKey)
	}
	fmt.Printf("p7 CRLs:\n")
	for idx, crl := range p7.CRLs {
		fmt.Printf("   [%d] %+v\n", idx, crl)
	}
	fmt.Printf("p7 Signers:\n")
	for idx, signer := range p7.Signers {
		name := new(pkix.Name)
		name.FillFromRDNSequence(&signer.IssuerAndSerialNumber.IssuerName)
		fmt.Printf("   [%d] %s (Serial# %s)\n", idx, name.CommonName, signer.IssuerAndSerialNumber.SerialNumber)
		fmt.Printf("        Digest Algorithm: %s\n", signer.DigestAlgorithm.Algorithm)
		fmt.Printf("        Encryption Algorithm: %s\n", signer.DigestEncryptionAlgorithm.Algorithm)
		fmt.Printf("        Digest: %q\n", base64.StdEncoding.EncodeToString(signer.EncryptedDigest))
	}
	//fmt.Printf("p7 Raw: %+v", p7.raw)
}

func TestVerify(t *testing.T) {
	example1, _ := ioutil.ReadFile("test_example.p7")
	p7, err := Parse(example1)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}
