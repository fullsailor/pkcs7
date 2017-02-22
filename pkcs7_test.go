package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
	expected := []byte("We the People")
	if bytes.Compare(p7.Content, expected) != 0 {
		t.Errorf("Signed content does not match.\n\tExpected:%s\n\tActual:%s", expected, p7.Content)

	}
}

func TestVerifyEC2(t *testing.T) {
	fixture := UnmarshalTestFixture(EC2IdentityDocumentFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Certificates = []*x509.Certificate{fixture.Certificate}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyAppStore(t *testing.T) {
	fixture := UnmarshalTestFixture(AppStoreReceiptFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyFirefoxAddon(t *testing.T) {
	fixture := UnmarshalTestFixture(FirefoxAddonFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Content = FirefoxAddonContent
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(FirefoxAddonRootCert)
	if err := p7.VerifyWithChain(certPool); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
	// Verify the certificate chain to make sure the identified root
	// is the one we expect
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, p7.Signers[0].IssuerAndSerialNumber)
	if ee == nil {
		t.Errorf("No end-entity certificate found for signer")
	}
	signingTime, _ := time.Parse(time.RFC3339, "2017-02-23 09:06:16-05:00")
	chains, err := verifyCertChain(ee, p7.Certificates, certPool, signingTime)
	if err != nil {
		t.Error(err)
	}
	if len(chains) != 1 {
		t.Errorf("Expected to find one chain, but found %d", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Errorf("Expected to find three certificates in chain, but found %d", len(chains[0]))
	}
	if chains[0][0].Subject.CommonName != "tabscope@xuldev.org" {
		t.Errorf("Expected to find EE certificate with subject 'tabscope@xuldev.org', but found '%s'", chains[0][0].Subject.CommonName)
	}
	if chains[0][1].Subject.CommonName != "production-signing-ca.addons.mozilla.org" {
		t.Errorf("Expected to find EE certificate with subject 'production-signing-ca.addons.mozilla.org', but found '%s'", chains[0][1].Subject.CommonName)
	}
	if chains[0][2].Subject.CommonName != "root-ca-production-amo" {
		t.Errorf("Expected to find EE certificate with subject 'root-ca-production-amo', but found '%s'", chains[0][2].Subject.CommonName)
	}
}

func TestDecrypt(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err != nil {
		t.Errorf("Cannot Decrypt with error: %v", err)
	}
	expected := []byte("This is a test")
	if bytes.Compare(content, expected) != 0 {
		t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}

}

func TestSign(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			var parents []*x509.Certificate
			parents = append(parents, interCert.Certificate)
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				for _, testDetach := range []bool{false, true} {
					log.Printf("test %s/%s/%s detached %t\n", sigalgroot, sigalginter, sigalgsigner, testDetach)
					toBeSigned, err := NewSignedData(content)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if err := toBeSigned.AddSignerWithParents(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						toBeSigned.Detach()
					}
					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						p7.Content = content
					}
					if bytes.Compare(content, p7.Content) != 0 {
						t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
					}
					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
				}
			}
		}
	}
}

func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestOpenSSLVerifyDetachedSignature(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for i, sigalg := range sigalgs {
		log.Printf("test case %d sigalg %s\n", i, sigalg)
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalg, true)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot generate root cert: %s", i, sigalg, err)
		}
		interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate CA", rootCert, sigalg, true)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot generate intermediate cert: %s", i, sigalg, err)
		}
		var parents []*x509.Certificate
		parents = append(parents, interCert.Certificate)
		signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalg, false)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot generate signer cert: %s", i, sigalg, err)
		}
		toBeSigned, err := NewSignedData(content)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot initialize signed data: %s", i, sigalg, err)
		}
		if err := toBeSigned.AddSignerWithParents(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		toBeSigned.Detach()
		signed, err := toBeSigned.Finish()
		if err != nil {
			t.Fatalf("test case %d sigalg %s: ccannot finish signing data: %s", i, sigalg, err)
		}
		pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

		// write the root cert to a temp file
		tmpRootCertFile, err := ioutil.TempFile("", "pkcs7TestRootCA")
		if err != nil {
			t.Fatal(err)
		}
		//defer os.Remove(tmpRootCertFile.Name()) // clean up
		fd, err := os.OpenFile(tmpRootCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Certificate.Raw})
		fd.Close()

		// write the signature to a temp file
		tmpSignatureFile, err := ioutil.TempFile("", "pkcs7Signature")
		if err != nil {
			t.Fatal(err)
		}
		//defer os.Remove(tmpSignatureFile.Name()) // clean up
		ioutil.WriteFile(tmpSignatureFile.Name(), signed, 0755)

		// write the content to a temp file
		tmpContentFile, err := ioutil.TempFile("", "pkcs7Content")
		if err != nil {
			t.Fatal(err)
		}
		//defer os.Remove(tmpContentFile.Name()) // clean up
		ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

		// call openssl to verify the signature on the content using the root
		opensslCMD := exec.Command("openssl", "smime", "-verify",
			"-in", tmpSignatureFile.Name(), "-inform", "DER",
			"-content", tmpContentFile.Name(),
			"-CAfile", tmpRootCertFile.Name())
		out, err := opensslCMD.Output()
		t.Logf("%s", out)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: openssl command failed with %s", i, sigalg, err)
		}
	}
}

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			ContentEncryptionAlgorithm = mode

			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if bytes.Compare(plaintext, result) != 0 {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{Attribute{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if bytes.Compare(test.Expected, padded) != 0 {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}

var test1024Key, test2048Key, test3072Key, test4096Key *rsa.PrivateKey

func init() {
	test1024Key = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("123024078101403810516614073341068864574068590522569345017786163424062310013967742924377390210586226651760719671658568413826602264886073432535341149584680111145880576802262550990305759285883150470245429547886689754596541046564560506544976611114898883158121012232676781340602508151730773214407220733898059285561"),
			E: 65537,
		},
		D: fromBase10("118892427340746627750435157989073921703209000249285930635312944544706203626114423392257295670807166199489096863209592887347935991101581502404113203993092422730000157893515953622392722273095289787303943046491132467130346663160540744582438810535626328230098940583296878135092036661410664695896115177534496784545"),
		Primes: []*big.Int{
			fromBase10("12172745919282672373981903347443034348576729562395784527365032103134165674508405592530417723266847908118361582847315228810176708212888860333051929276459099"),
			fromBase10("10106518193772789699356660087736308350857919389391620140340519320928952625438936098550728858345355053201610649202713962702543058578827268756755006576249339"),
		},
	}
	test1024Key.Precompute()
	test2048Key = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557"),
			E: 3,
		},
		D: fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433"),
			fromBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029"),
		},
	}
	test2048Key.Precompute()
	test3072Key = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("4799422180968749215324244710281712119910779465109490663934897082847293004098645365195947978124390029272750644394844443980065532911010718425428791498896288210928474905407341584968381379157418577471272697781778686372450913810019702928839200328075568223462554606149618941566459398862673532997592879359280754226882565483298027678735544377401276021471356093819491755877827249763065753555051973844057308627201762456191918852016986546071426986328720794061622370410645440235373576002278045257207695462423797272017386006110722769072206022723167102083033531426777518054025826800254337147514768377949097720074878744769255210076910190151785807232805749219196645305822228090875616900385866236956058984170647782567907618713309775105943700661530312800231153745705977436176908325539234432407050398510090070342851489496464612052853185583222422124535243967989533830816012180864309784486694786581956050902756173889941244024888811572094961378021"),
			E: 65537,
		},
		D: fromBase10("4068124900056380177006532461065648259352178312499768312132802353620854992915205894105621345694615110794369150964768050224096623567443679436821868510233726084582567244003894477723706516831312989564775159596496449435830457803384416702014837685962523313266832032687145914871879794104404800823188153886925022171560391765913739346955738372354826804228989767120353182641396181570533678315099748218734875742705419933837638038793286534641711407564379950728858267828581787483317040753987167237461567332386718574803231955771633274184646232632371006762852623964054645811527580417392163873708539175349637050049959954373319861427407953413018816604365474462455009323937599275324390953644555294418021286807661559165324810415569396577697316798600308544755741549699523972971375304826663847015905713096287495342701286542193782001358775773848824496321550110946106870685499577993864871847542645561943034990484973293461948058147956373115641615329"),
		Primes: []*big.Int{
			fromBase10("2378529069722721185825622840841310902793949682948530343491428052737890236476884657507685118578733560141370511507721598189068683665232991988491561624429938984370132428230072355214627085652359350722926394699707232921674771664421591347888367477300909202851476404132163673865768760147403525700174918450753162242834161458300343282159799476695001920226357456953682236859505243928716782707623075239350380352265954107362618991716602898266999700316937680986690964564264877"),
			fromBase10("2017811025336026464312837780072272578817919741496395062543647660689775637351085991504709917848745137013798005682591633910555599626950744674459976829106750083386168859581016361317479081273480343110649405858059581933773354781034946787147300862495438979895430001323443224335618577322449133208754541656374335100929456885995320929464029817626916719434010943205170760536768893924932021302887114400922813817969176636993508191950649313115712159241971065134077636674146073"),
		},
	}
	test3072Key.Precompute()
	test4096Key = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("633335480064287130853997429184971616419051348693342219741748040433588285601270210251206421401040394238592139790962887290698043839174341843721930134010306454716566698330215646704263665452264344664385995704186692432827662862845900348526672531755932642433662686500295989783595767573119607065791980381547677840410600100715146047382485989885183858757974681241303484641390718944520330953604501686666386926996348457928415093305041429178744778762826377713889019740060910363468343855830206640274442887621960581569183233822878661711798998132931623726434336448716605363514220760343097572198620479297583609779817750646169845195672483600293522186340560792255595411601450766002877850696008003794520089358819042318331840490155176019070646738739580486357084733208876620846449161909966690602374519398451042362690200166144326179405976024265116931974936425064291406950542193873313447617169603706868220189295654943247311295475722243471700112334609817776430552541319671117235957754556272646031356496763094955985615723596562217985372503002989591679252640940571608314743271809251568670314461039035793703429977801961867815257832671786542212589906513979094156334941265621017752516999186481477500481433634914622735206243841674973785078408289183000133399026553"),
			E: 65537,
		},
		D: fromBase10("439373650557744155078930178606343279553665694488479749802070836418412881168612407941793966086633543867614175621952769177088930851151267623886678906158545451731745754402575409204816390946376103491325109185445659065122640946673660760274557781540431107937331701243915001777636528502669576801704352961341634812275635811512806966908648671988644114352046582195051714797831307925775689566757438907578527366568747104508496278929566712224252103563340770696548181508180254674236716995730292431858611476396845443056967589437890065663497768422598977743046882539288481002449571403783500529740184608873520856954837631427724158592309018382711485601884461168736465751756282510065053161144027097169985941910909130083273691945578478173708396726266170473745329617793866669307716920992380350270584929908460462802627239204245339385636926433446418108504614031393494119344916828744888432279343816084433424594432427362258172264834429525166677273382617457205387388293888430391895615438030066428745187333897518037597413369705720436392869403948934993623418405908467147848576977008003556716087129242155836114780890054057743164411952731290520995017097151300091841286806603044227906213832083363876549637037625314539090155417589796428888619937329669464810549362433"),
		Primes: []*big.Int{
			fromBase10("25745433817240673759910623230144796182285844101796353869339294232644316274580053211056707671663014355388701931204078502829809738396303142990312095225333440050808647355535878394534263839500592870406002873182360027755750148248672968563366185348499498613479490545488025779331426515670185366021612402246813511722553210128074701620113404560399242413747318161403908617342170447610792422053460359960010544593668037305465806912471260799852789913123044326555978680190904164976511331681163576833618899773550873682147782263100803907156362439021929408298804955194748640633152519828940133338948391986823456836070708197320166146761"),
			fromBase10("24599914864909676687852658457515103765368967514652318497893275892114442089314173678877914038802355565271545910572804267918959612739009937926962653912943833939518967731764560204997062096919833970670512726396663920955497151415639902788974842698619579886297871162402643104696160155894685518587660015182381685605752989716946154299190561137541792784125356553411300817844325739404126956793095254412123887617931225840421856505925283322918693259047428656823141903489964287619982295891439430302405252447010728112098326033634688757933930065610737780413018498561434074501822951716586796047404555397992425143397497639322075233073"),
		},
	}
	test4096Key.Precompute()
}

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

type certKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *crypto.PrivateKey
}

func createTestCertificate(sigAlg x509.SignatureAlgorithm) (certKeyPair, error) {
	signer, err := createTestCertificateByIssuer("Eddard Stark", nil, sigAlg, true)
	if err != nil {
		return certKeyPair{}, err
	}
	pair, err := createTestCertificateByIssuer("Jon Snow", signer, sigAlg, false)
	if err != nil {
		return certKeyPair{}, err
	}
	return *pair, nil
}

func createTestCertificateByIssuer(name string, issuer *certKeyPair, sigAlg x509.SignatureAlgorithm, isCA bool) (*certKeyPair, error) {
	var (
		err        error
		priv       crypto.PrivateKey
		derCert    []byte
		issuerCert *x509.Certificate
		issuerKey  crypto.PrivateKey
	)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	switch sigAlg {
	case x509.SHA1WithRSA:
		priv = test1024Key
	case x509.SHA256WithRSA:
		priv = test2048Key
	case x509.SHA384WithRSA:
		priv = test3072Key
	case x509.SHA512WithRSA:
		priv = test4096Key
	case x509.ECDSAWithSHA1:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA512:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}
	if issuer != nil {
		template.SignatureAlgorithm = 0
		issuerCert = issuer.Certificate
		issuerKey = *issuer.PrivateKey
	} else {
		// no issuer given,make this a self-signed root cert
		issuerCert = &template
		issuerKey = priv
		template.SignatureAlgorithm = sigAlg
	}
	log.Println("creating cert", name, "issued by", issuerCert.Subject.CommonName, "with sigalg", sigAlg)
	switch priv.(type) {
	case *rsa.PrivateKey:
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*rsa.PrivateKey).Public(), issuerKey.(*rsa.PrivateKey))
		case *ecdsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*rsa.PrivateKey).Public(), issuerKey.(*ecdsa.PrivateKey))
		}
	case *ecdsa.PrivateKey:
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*ecdsa.PrivateKey).Public(), issuerKey.(*rsa.PrivateKey))
		case *ecdsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*ecdsa.PrivateKey).Public(), issuerKey.(*ecdsa.PrivateKey))
		}
	}
	if err != nil {
		return nil, err
	}
	if len(derCert) == 0 {
		return nil, fmt.Errorf("no certificate created, probably due to wrong keys. types were %T and %T", priv, issuerKey)
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &certKeyPair{
		Certificate: cert,
		PrivateKey:  &priv,
	}, nil
}

type TestFixture struct {
	Input       []byte
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func UnmarshalTestFixture(testPEMBlock string) TestFixture {
	var result TestFixture
	var derBlock *pem.Block
	var pemBlock = []byte(testPEMBlock)
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		switch derBlock.Type {
		case "PKCS7":
			result.Input = derBlock.Bytes
		case "CERTIFICATE":
			result.Certificate, _ = x509.ParseCertificate(derBlock.Bytes)
		case "PRIVATE KEY":
			result.PrivateKey, _ = x509.ParsePKCS1PrivateKey(derBlock.Bytes)
		}
	}

	return result
}

func MarshalTestFixture(t TestFixture, w io.Writer) {
	if t.Input != nil {
		pem.Encode(w, &pem.Block{Type: "PKCS7", Bytes: t.Input})
	}
	if t.Certificate != nil {
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: t.Certificate.Raw})
	}
	if t.PrivateKey != nil {
		pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(t.PrivateKey)})
	}
}

var SignedTestFixture = `
-----BEGIN PKCS7-----
MIIDVgYJKoZIhvcNAQcCoIIDRzCCA0MCAQExCTAHBgUrDgMCGjAcBgkqhkiG9w0B
BwGgDwQNV2UgdGhlIFBlb3BsZaCCAdkwggHVMIIBQKADAgECAgRpuDctMAsGCSqG
SIb3DQEBCzApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3Rh
cmswHhcNMTUwNTA2MDQyNDQ4WhcNMTYwNTA2MDQyNDQ4WjAlMRAwDgYDVQQKEwdB
Y21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAqr+tTF4mZP5rMwlXp1y+crRtFpuLXF1zvBZiYMfIvAHwo1ta8E1IcyEP
J1jIiKMcwbzeo6kAmZzIJRCTezq9jwXUsKbQTvcfOH9HmjUmXBRWFXZYoQs/OaaF
a45deHmwEeMQkuSWEtYiVKKZXtJOtflKIT3MryJEDiiItMkdybUCAwEAAaMSMBAw
DgYDVR0PAQH/BAQDAgCgMAsGCSqGSIb3DQEBCwOBgQDK1EweZWRL+f7Z+J0kVzY8
zXptcBaV4Lf5wGZJLJVUgp33bpLNpT3yadS++XQJ+cvtW3wADQzBSTMduyOF8Zf+
L7TjjrQ2+F2HbNbKUhBQKudxTfv9dJHdKbD+ngCCdQJYkIy2YexsoNG0C8nQkggy
axZd/J69xDVx6pui3Sj8sDGCATYwggEyAgEBMDEwKTEQMA4GA1UEChMHQWNtZSBD
bzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrAgRpuDctMAcGBSsOAwIaoGEwGAYJKoZI
hvcNAQkDMQsGCSqGSIb3DQEHATAgBgkqhkiG9w0BCQUxExcRMTUwNTA2MDAyNDQ4
LTA0MDAwIwYJKoZIhvcNAQkEMRYEFG9D7gcTh9zfKiYNJ1lgB0yTh4sZMAsGCSqG
SIb3DQEBAQSBgFF3sGDU9PtXty/QMtpcFa35vvIOqmWQAIZt93XAskQOnBq4OloX
iL9Ct7t1m4pzjRm0o9nDkbaSLZe7HKASHdCqijroScGlI8M+alJ8drHSFv6ZIjnM
FIwIf0B2Lko6nh9/6mUXq7tbbIHa3Gd1JUVire/QFFtmgRXMbXYk8SIS
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1TCCAUCgAwIBAgIEabg3LTALBgkqhkiG9w0BAQswKTEQMA4GA1UEChMHQWNt
ZSBDbzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrMB4XDTE1MDUwNjA0MjQ0OFoXDTE2
MDUwNjA0MjQ0OFowJTEQMA4GA1UEChMHQWNtZSBDbzERMA8GA1UEAxMISm9uIFNu
b3cwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKq/rUxeJmT+azMJV6dcvnK0
bRabi1xdc7wWYmDHyLwB8KNbWvBNSHMhDydYyIijHMG83qOpAJmcyCUQk3s6vY8F
1LCm0E73Hzh/R5o1JlwUVhV2WKELPzmmhWuOXXh5sBHjEJLklhLWIlSimV7STrX5
SiE9zK8iRA4oiLTJHcm1AgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIAoDALBgkqhkiG
9w0BAQsDgYEAytRMHmVkS/n+2fidJFc2PM16bXAWleC3+cBmSSyVVIKd926SzaU9
8mnUvvl0CfnL7Vt8AA0MwUkzHbsjhfGX/i+04460Nvhdh2zWylIQUCrncU37/XSR
3Smw/p4AgnUCWJCMtmHsbKDRtAvJ0JIIMmsWXfyevcQ1ceqbot0o/LA=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQCqv61MXiZk/mszCVenXL5ytG0Wm4tcXXO8FmJgx8i8AfCjW1rw
TUhzIQ8nWMiIoxzBvN6jqQCZnMglEJN7Or2PBdSwptBO9x84f0eaNSZcFFYVdlih
Cz85poVrjl14ebAR4xCS5JYS1iJUople0k61+UohPcyvIkQOKIi0yR3JtQIDAQAB
AoGBAIPLCR9N+IKxodq11lNXEaUFwMHXc1zqwP8no+2hpz3+nVfplqqubEJ4/PJY
5AgbJoIfnxVhyBXJXu7E+aD/OPneKZrgp58YvHKgGvvPyJg2gpC/1Fh0vQB0HNpI
1ZzIZUl8ZTUtVgtnCBUOh5JGI4bFokAqrT//Uvcfd+idgxqBAkEA1ZbP/Kseld14
qbWmgmU5GCVxsZRxgR1j4lG3UVjH36KXMtRTm1atAam1uw3OEGa6Y3ANjpU52FaB
Hep5rkk4FQJBAMynMo1L1uiN5GP+KYLEF5kKRxK+FLjXR0ywnMh+gpGcZDcOae+J
+t1gLoWBIESH/Xt639T7smuSfrZSA9V0EyECQA8cvZiWDvLxmaEAXkipmtGPjKzQ
4PsOtkuEFqFl07aKDYKmLUg3aMROWrJidqsIabWxbvQgsNgSvs38EiH3wkUCQQCg
ndxb7piVXb9RBwm3OoU2tE1BlXMX+sVXmAkEhd2dwDsaxrI3sHf1xGXem5AimQRF
JBOFyaCnMotGNioSHY5hAkEAxyXcNixQ2RpLXJTQZtwnbk0XDcbgB+fBgXnv/4f3
BCvcu85DqJeJyQv44Oe1qsXEX9BfcQIOVaoep35RPlKi9g==
-----END PRIVATE KEY-----`

// Content is "This is a test"
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBFwYJKoZIhvcNAQcDoIIBCDCCAQQCAQAxgcowgccCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMAsGCSqGSIb3
DQEBAQSBgKyP/5WlRTZD3dWMrLOX6QRNDrXEkQjhmToRwFZdY3LgUh25ZU0S/q4G
dHPV21Fv9lQD+q7l3vfeHw8M6Z1PKi9sHMVfxAkQpvaI96DTIT3YHtuLC1w3geCO
8eFWTq2qS4WChSuS/yhYosjA1kTkE0eLnVZcGw0z/WVuEZznkdyIMDIGCSqGSIb3
DQEHATARBgUrDgMCBwQImpKsUyMPpQigEgQQRcWWrCRXqpD5Njs0GkJl+g==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`

var EC2IdentityDocumentFixture = `
-----BEGIN PKCS7-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCA
JIAEggGmewogICJwcml2YXRlSXAiIDogIjE3Mi4zMC4wLjI1MiIsCiAgImRldnBh
eVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1
cy1lYXN0LTFhIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3Rh
bmNlSWQiIDogImktZjc5ZmU1NmMiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVs
bCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIg
OiAiMTIxNjU5MDE0MzM0IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwK
ICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDhUMDM6MDE6MzhaIiwKICAiYXJj
aGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJy
YW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAA
AAAxggEYMIIBFAIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5n
dG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2Vi
IFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDgwMzAxNDRaMCMG
CSqGSIb3DQEJBDEWBBTuUc28eBXmImAautC+wOjqcFCBVjAJBgcqhkjOOAQDBC8w
LQIVAKA54NxGHWWCz5InboDmY/GHs33nAhQ6O/ZI86NwjA9Vz3RNMUJrUPU5tAAA
AAAAAA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`

var AppStoreReceiptFixture = `
-----BEGIN PKCS7-----
MIITtgYJKoZIhvcNAQcCoIITpzCCE6MCAQExCzAJBgUrDgMCGgUAMIIDVwYJKoZI
hvcNAQcBoIIDSASCA0QxggNAMAoCAQgCAQEEAhYAMAoCARQCAQEEAgwAMAsCAQEC
AQEEAwIBADALAgEDAgEBBAMMATEwCwIBCwIBAQQDAgEAMAsCAQ8CAQEEAwIBADAL
AgEQAgEBBAMCAQAwCwIBGQIBAQQDAgEDMAwCAQoCAQEEBBYCNCswDAIBDgIBAQQE
AgIAjTANAgENAgEBBAUCAwFgvTANAgETAgEBBAUMAzEuMDAOAgEJAgEBBAYCBFAy
NDcwGAIBAgIBAQQQDA5jb20uemhpaHUudGVzdDAYAgEEAgECBBCS+ZODNMHwT1Nz
gWYDXyWZMBsCAQACAQEEEwwRUHJvZHVjdGlvblNhbmRib3gwHAIBBQIBAQQU4nRh
YCEZx70Flzv7hvJRjJZckYIwHgIBDAIBAQQWFhQyMDE2LTA3LTIzVDA2OjIxOjEx
WjAeAgESAgEBBBYWFDIwMTMtMDgtMDFUMDc6MDA6MDBaMD0CAQYCAQEENbR21I+a
8+byMXo3NPRoDWQmSXQF2EcCeBoD4GaL//ZCRETp9rGFPSg1KekCP7Kr9HAqw09m
MEICAQcCAQEEOlVJozYYBdugybShbiiMsejDMNeCbZq6CrzGBwW6GBy+DGWxJI91
Y3ouXN4TZUhuVvLvN1b0m5T3ggQwggFaAgERAgEBBIIBUDGCAUwwCwICBqwCAQEE
AhYAMAsCAgatAgEBBAIMADALAgIGsAIBAQQCFgAwCwICBrICAQEEAgwAMAsCAgaz
AgEBBAIMADALAgIGtAIBAQQCDAAwCwICBrUCAQEEAgwAMAsCAga2AgEBBAIMADAM
AgIGpQIBAQQDAgEBMAwCAgarAgEBBAMCAQEwDAICBq4CAQEEAwIBADAMAgIGrwIB
AQQDAgEAMAwCAgaxAgEBBAMCAQAwGwICBqcCAQEEEgwQMTAwMDAwMDIyNTMyNTkw
MTAbAgIGqQIBAQQSDBAxMDAwMDAwMjI1MzI1OTAxMB8CAgaoAgEBBBYWFDIwMTYt
MDctMjNUMDY6MjE6MTFaMB8CAgaqAgEBBBYWFDIwMTYtMDctMjNUMDY6MjE6MTFa
MCACAgamAgEBBBcMFWNvbS56aGlodS50ZXN0LnRlc3RfMaCCDmUwggV8MIIEZKAD
AgECAggO61eH554JjTANBgkqhkiG9w0BAQUFADCBljELMAkGA1UEBhMCVVMxEzAR
BgNVBAoMCkFwcGxlIEluYy4xLDAqBgNVBAsMI0FwcGxlIFdvcmxkd2lkZSBEZXZl
bG9wZXIgUmVsYXRpb25zMUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNTExMTMw
MjE1MDlaFw0yMzAyMDcyMTQ4NDdaMIGJMTcwNQYDVQQDDC5NYWMgQXBwIFN0b3Jl
IGFuZCBpVHVuZXMgU3RvcmUgUmVjZWlwdCBTaWduaW5nMSwwKgYDVQQLDCNBcHBs
ZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczETMBEGA1UECgwKQXBwbGUg
SW5jLjELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQClz4H9JaKBW9aH7SPaMxyO4iPApcQmyz3Gn+xKDVWG/6QC15fKOVRtfX+yVBid
xCxScY5ke4LOibpJ1gjltIhxzz9bRi7GxB24A6lYogQ+IXjV27fQjhKNg0xbKmg3
k8LyvR7E0qEMSlhSqxLj7d0fmBWQNS3CzBLKjUiB91h4VGvojDE2H0oGDEdU8zeQ
uLKSiX1fpIVK4cCc4Lqku4KXY/Qrk8H9Pm/KwfU8qY9SGsAlCnYO3v6Z/v/Ca/Vb
XqxzUUkIVonMQ5DMjoEC0KCXtlyxoWlph5AQaCYmObgdEHOwCl3Fc9DfdjvYLdmI
HuPsB8/ijtDT+iZVge/iA0kjAgMBAAGjggHXMIIB0zA/BggrBgEFBQcBAQQzMDEw
LwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtd3dkcjA0
MB0GA1UdDgQWBBSRpJz8xHa3n6CK9E31jzZd7SsEhTAMBgNVHRMBAf8EAjAAMB8G
A1UdIwQYMBaAFIgnFwmpthhgi+zruvZHWcVSVKO3MIIBHgYDVR0gBIIBFTCCAREw
ggENBgoqhkiG92NkBQYBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9u
IHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5j
ZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25k
aXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0
aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3
LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wDgYDVR0PAQH/BAQDAgeA
MBAGCiqGSIb3Y2QGCwEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQANphvTLj3jWysH
bkKWbNPojEMwgl/gXNGNvr0PvRr8JZLbjIXDgFnf4+LXLgUUrA3btrj+/DUufMut
F2uOfx/kd7mxZ5W0E16mGYZ2+FogledjjA9z/Ojtxh+umfhlSFyg4Cg6wBA3Lbmg
BDkfc7nIBf3y3n8aKipuKwH8oCBc2et9J6Yz+PWY4L5E27FMZ/xuCk/J4gao0pfz
p45rUaJahHVl0RYEYuPBX/UIqc9o2ZIAycGMs/iNAGS6WGDAfK+PdcppuVsq1h1o
bphC9UynNxmbzDscehlD86Ntv0hgBgw2kivs3hi1EdotI9CO/KBpnBcbnoB7OUdF
MGEvxxOoMIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjEL
MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxl
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENB
MB4XDTEzMDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVT
MRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUg
RGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERl
dmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0
U3rOfGOAYXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkV
CBmsqtsqMu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8
V25nNYB2NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHl
d0WNUEi6Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1q
arunFjVg0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGj
gaYwgaMwHQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQF
MAMBAf8wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcw
JTAjoCGgH4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/
BAQDAgGGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Z
viz1smwvj+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/N
w0Uwj6ODDc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJ
TleMa1s8Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1V
AKmuu0swruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur
+cmV6U/kTecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxR
pVzscYqCtGwPDBUfMIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQsw
CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUg
Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0Ew
HhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne
+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjcz
y8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQ
Z48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCS
C7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINB
hzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIB
djAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9Bp
R5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/
CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcC
ARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCB
thqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFz
c3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJk
IHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5
IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3
DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizU
sZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJ
fBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr
1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltk
wGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIq
xw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUhMYIByzCCAccCAQEwgaMwgZYxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBX
b3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29y
bGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
dHkCCA7rV4fnngmNMAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEggEAasPtnide
NWyfUtewW9OSgcQA8pW+5tWMR0469cBPZR84uJa0gyfmPspySvbNOAwnrwzZHYLa
ujOxZLip4DUw4F5s3QwUa3y4BXpF4J+NSn9XNvxNtnT/GcEQtCuFwgJ0o3F0ilhv
MTHrwiwyx/vr+uNDqlORK8lfK+1qNp+A/kzh8eszMrn4JSeTh9ZYxLHE56WkTQGD
VZXl0gKgxSOmDrcp1eQxdlymzrPv9U60wUJ0bkPfrU9qZj3mJrmrkQk61JTe3j6/
QfjfFBG9JG2mUmYQP1KQ3SypGHzDW8vngvsGu//tNU0NFfOqQu4bYU4VpQl0nPtD
4B85NkrgvQsWAQ==
-----END PKCS7-----`

var FirefoxAddonContent = []byte(`Signature-Version: 1.0
MD5-Digest-Manifest: KjRavc6/KNpuT1QLcB/Gsg==
SHA1-Digest-Manifest: 5Md5nUg+U7hQ/UfzV+xGKWOruVI=

`)

var FirefoxAddonFixture = `
-----BEGIN PKCS7-----
MIIQTAYJKoZIhvcNAQcCoIIQPTCCEDkCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3
DQEHAaCCDL0wggW6MIIDoqADAgECAgYBVpobWVwwDQYJKoZIhvcNAQELBQAwgcUx
CzAJBgNVBAYTAlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYD
VQQLEyZNb3ppbGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTExMC8G
A1UEAxMocHJvZHVjdGlvbi1zaWduaW5nLWNhLmFkZG9ucy5tb3ppbGxhLm9yZzE0
MDIGCSqGSIb3DQEJARYlc2VydmljZXMtb3BzK2FkZG9uc2lnbmluZ0Btb3ppbGxh
LmNvbTAeFw0xNjA4MTcyMDA0NThaFw0yMTA4MTYyMDA0NThaMHYxEzARBgNVBAsT
ClByb2R1Y3Rpb24xCzAJBgNVBAYTAlVTMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3
MQ8wDQYDVQQKEwZBZGRvbnMxCzAJBgNVBAgTAkNBMRwwGgYDVQQDFBN0YWJzY29w
ZUB4dWxkZXYub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv6e0
mPD8dt4J8HTNNq4ODns2DV6Weh1hllCIFvOeu1u3UrR03st0BMY8OXYwr/NvRVjg
bA8gRySWAL+XqLzbhtXNeNegAoxrF+3mYY5rJjsLj/FGI6P6OXjngqwgm9VTBl7m
jh/KXBSwYoUcavJo6cmk8sCFwoblyQiv+tsWaUCOI6zMzubNtIS+GFvET9y/VZMP
j6mk8O10wBgJF5MMtA19va3qXy7aCZ7DnZp1l3equd/L6t324TtXoqx6xWQKo6TM
I0mcTlKvm6TKegTGBCyGn3JRARoIJv4AW1qqgyaHXf9EoY2pKT8Avkri5++NuSJ6
jtO4k/diBA2MZU20U0KGffYZNTxKDqd6XtI6y1tJPd/OWRFyU+mHntkcm9sar7L3
nPKujHRox2re10ec1WBnJE3PjlAoesNjxzp+xs2mGGc8DX9NuWn+1uK9xmgGIIMl
OFfyQ4s0G6hKp5goFcrFZxmexu0ZahOs8vZf8xDBW7yR1zToQElOXHvrscM386os
kOF9IxQZfcCoPuNQVg1haCONNkx0oau3RQQlOSAZtC79b+rBjQ5JYfjRLYAworf2
xQaprCh33TD1dTBrvzEbCGszgkN53Vqh5TFBjbU/NyldOkGvK8Xf6WhT5u+aftnV
lbuE2McAg6x1AlloUZq6PNTBpz7zypcIISnQ+y8CAwEAATANBgkqhkiG9w0BAQsF
AAOCAgEAIBoo2+OEYNCgP/IbUj9azaf/lde1q4AK/uTMoUeS5WcrXd8aqA0Y1qV7
xUALgDQAExXgqcOMGu4mPMaoZDgwGI4Tj7XPJQq5Z5zYxpRf/Wtzae33T9BF6QPW
v5xiRYuol+FbEtqRHZqxDWtIrd1MWBy3wjO3pLPdzDM9jWh+HLxdGWThJszaZp3T
CqsOx+l9W0Q7qM5ioZpHStgXDfhw38Lg++kLnzcX9MqsjYyezdwE4krqW6hK3+4S
0LZE4dTgsy8JULkyAF3HrPWEXESnD7c4mx6owZe+BNDK5hsVM/obAqH7sJq/igbM
5N1l832p/ws8l5xKOr3qBWSzWn6u7ExvqG6Ckh0foJOVXvzGqvrXcoiBGV8S9Z7c
DghUvMt6b0pZ0ildRCHfTUz7eG3g4MhfbjupR7b+L9FWEJhcd/H0dxpw7SKYha/n
ePuRL7MXmbW8WLMqO/ImxzL8TPOB3pUg3nITfubV6gpPBmn+0nwbqYUmggJuwgvK
I2GpN2Ny6EErZy17EEgyhJygJZMj+UzQjC781xxsl3ljpYEqqwgRLIZBSBUD5dXj
XBuU24w162SeSyHZzkBbuv6lr52pqoZyFrG29DCHECgO9ZmNWgSpiWSkh+vExAG7
wNs0y61t2HUG+BCMGPQ9sOzouyTfrnLVAWwzswGftFYQfoIBeJIwggb7MIIE46AD
AgECAgMQAAIwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCVVMxHDAaBgNVBAoT
E01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1
Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNhLXByb2R1Y3Rp
b24tYW1vMB4XDTE1MDMxNzIzNTI0MloXDTI1MDMxNDIzNTI0MlowgcUxCzAJBgNV
BAYTAlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZN
b3ppbGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTExMC8GA1UEAxMo
cHJvZHVjdGlvbi1zaWduaW5nLWNhLmFkZG9ucy5tb3ppbGxhLm9yZzE0MDIGCSqG
SIb3DQEJARYlc2VydmljZXMtb3BzK2FkZG9uc2lnbmluZ0Btb3ppbGxhLmNvbTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMLMM9m2HBLhCiO9mhljpehT
hxpzlCnxluzDZ51I/H7MvBbIvZBm9zSpHdffubSsak2qYE69d+ebTa/CK83WIosM
24/2Qp7n/GGaPJcCC4Y3JkrCsgA8+wV2MbFlKSv+qMdvI/sE3BPYDMCjVPMhHmIP
XaPWd42OoHpI8R3GGUtVnR3Hm76pa2+v6TwgeMiO8om+ogGufiyv6FNMZ5NuY1Z9
aLNEvehnAzSfddQyki+6FJd7XkgZbP7pb1Kl8yYgiy4piBerJ9H09uPehffE3Ell
3cApQL3+0kjaUX4scMjuNQDMKziRZkYgJAM+qA9WA5Jn77AjerQBWQeEev1PWHYh
0IDlgS/a0bjKmVjNZYG6adrY/R5/whzWGFCIE1UfhPm6PdN0557qvF838C2RFHsI
KzV6KQf0chMjpa02tPaIctjVhnDQZZNKm2ZfLOt9kQ57Is/e6KxH7pYMit46+s99
lYM7ZquvWbK19b1Ili/6S1BxSzd3wztgfN5jGsc+jCCYLm+AcVtfNKc8cFZHXKrB
CwhGmdbWDSBCicZNA7FKJpO3oIx26VPF2XUldA/T5Mh/POGLilK3t9m9qbjEyDp1
EwoBToOR/aMrdnNYvSWp0g/GHMzSfJjjXyAqrZY2itam/IJd8r9FoRAzevPt/zTX
BET3INoiCDGRH0XrxUYtAgMGVTejggE5MIIBNTAMBgNVHRMEBTADAQH/MA4GA1Ud
DwEB/wQEAwIBBjAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUdHxf
FKXipZLjs20GqIUdNkQXH4gwgagGA1UdIwSBoDCBnYAUs7zqWHSr4W54KrKrnCMe
qGMsl7ehgYGkfzB9MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jw
b3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5n
IFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW+CAQEwMwYJ
YIZIAYb4QgEEBCYWJGh0dHA6Ly9hZGRvbnMubW96aWxsYS5vcmcvY2EvY3JsLnBl
bTANBgkqhkiG9w0BAQwFAAOCAgEArde/fdjb7TE0eH7Ij7xU4JbcSyhY3cQhVYCw
Fg+Q/2pj+NAfazcjUuLWA0Y/YZs9HOx6j+ZAqO4C/xfMP4RDs9IypxvzHDU6SXgD
RK6uOKtS07HXLcXgFUBvJEQhbT/h5+IQOA4/GcpCshfD6iyiBBi+IocR+tnKPCuZ
T3m1t60Eja/MkPKG/Gx8vSodHvlTTsJ2GzjUEANveCZOnlAdp9fjTvFZny9qqnbg
sfVbuTqKndbCFW5QLXfkna6jBqMrY0+CpMYY2oJ5gwpHbE/7hhukjxGCTcpv7r/O
M53bb/DZnybDlLLepacljvz7DBA1O1FFtEhf9MR+vyvmBpniAyKQhqG2hsVGurE1
nBcE+oteZWar2lMp6+etDAb9DRC+jZv0aEQs2o/qQwyD8AGquLgBsJq5Jz3gGxzn
4r3vGu2lV8VdzIm0C8sOFSWTmTZxQmJbF8xSsQBojnsvEah4DPER+eAt6qKolaWe
s4drJQjzFyC7HJn2VqalpCwbe9CdMB7eRqzeP6GujJBi80/gx0pAysUtuKKpH5IJ
WbXAOszfrjb3CaHafYZDnwPoOfj74ogFzjt2f54jwnU+ET/byfjZ7J8SLH316C1V
HrvFXcTzyMV4aRluVPjPg9x1G58hMIbeuT4GpwQUNdJ9uL8t65v0XwG2t6Y7jpRO
sFVxBtgxggNXMIIDUwIBATCB0DCBxTELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01v
emlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rp
b24gU2lnbmluZyBTZXJ2aWNlMTEwLwYDVQQDEyhwcm9kdWN0aW9uLXNpZ25pbmct
Y2EuYWRkb25zLm1vemlsbGEub3JnMTQwMgYJKoZIhvcNAQkBFiVzZXJ2aWNlcy1v
cHMrYWRkb25zaWduaW5nQG1vemlsbGEuY29tAgYBVpobWVwwCQYFKw4DAhoFAKBd
MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDgx
NzIwMDQ1OFowIwYJKoZIhvcNAQkEMRYEFAxlGvNFSx+Jqj70haE8b7UZk+2GMA0G
CSqGSIb3DQEBAQUABIICADsDlrucYRgwq9o2QSsO6X6cRa5Zu6w+1n07PTIyc1zn
Pi1cgkkWZ0kZBHDrJ5CY33yRQPl6I1tHXaq7SkOSdOppKhpUmBiKZxQRAZR21QHk
R3v1XS+st/o0N+0btv3YoplUifLIwtH89oolxqlStChELu7FuOBretdhx/z12ytA
EhIIS53o/XjDL7XKJbQA02vzOtOC/Eq6p8BI7F3y6pvtmJIRkeGv+u6ssJa6g5q8
74w8hHXaH94Z9+hDPqjNWlsXJHgPdAKiEjzDz9oLkvDyX4Pd8JMK5ILskirpG+hj
Q8jkTc5oYwyuSlBAUTGxW6ZbuOrtfVZvOVtRL/ixuiFiVlJ+JOQOxrtK19ukamsI
iacFlbLgiA7w0HCtm2DsT9aL67/1e4rJ0lv0MjnQYUMmKQy7g0Gd3+nQPU9pn+Lf
Z/UmSNWiJ8Csc/seDMyzT6jrzcGPfoSVaUowH0wGrI9If1snwcr+mMg7dWRGf1fm
y/dcVSzed0ax4LqDmike1EshU+51cKWWlnhyNHK4KH+0fNsBQ0c6clrFpGx9MPmV
YXie6C+LWkh5x12RU0sJt/SmSZV6q9VliIkX+yY3jBrC/pKgRahtcIyq46Da1E6K
lc15Euur3NfGow+nott0Z8XutpYdK/2vBKcIh9JOdkd+oe6pcIP6hnhHRp53wqmG
-----END PKCS7-----`

var FirefoxAddonRootCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`)
