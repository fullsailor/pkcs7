# pkcs7

This is a fork of an excellent [pkcs7](https://github.com/fullsailor/pkcs7) package. Copyright (c) 2015 Andrew Smith.

Notable additions to the original library are stream verifying and signing
functions. To verify signed message from reader `src` while writing contents to
some writer `dest` use:

```go
p7 := pkcs7.NewDecoder(r)
if err := p7.VerifyTo(dest); err != nil {
    // handle error
}
// use p7 fields and methods
```

To sign file `src` with known size to writer `dest`:

```go
p7 := pkcs7.NewEncoder(dest)
if err := p7.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
    // handle add signer error
}
if err = p7.SignFrom(r, size); err != nil {
    // handle write error
}
```

[![GoDoc](https://godoc.org/github.com/andviro/pkcs7?status.svg)](https://godoc.org/github.com/andviro/pkcs7)



# Original README

[![GoDoc](https://godoc.org/github.com/fullsailor/pkcs7?status.svg)](https://godoc.org/github.com/fullsailor/pkcs7)
[![Build Status](https://travis-ci.org/fullsailor/pkcs7.svg?branch=master)](https://travis-ci.org/fullsailor/pkcs7)

pkcs7 implements parsing and creating signed and enveloped messages.

- Documentation on [GoDoc](http://godoc.org/github.com/fullsailor/pkcs7)
