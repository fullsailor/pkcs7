// timestamp implements the timestamp Protocol (TSP) as specified in
// RFC3161 (Internet X.509 Public Key Infrastructure timestamp Protocol (TSP)).
//
// Original author: Paul van Brouwershaven
// Original source: https://github.com/digitorus/timestamp

package pkcs7 // import "go.mozilla.org/pkcs7"

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

// Timestamp represents an timestamp. See:
// https://tools.ietf.org/html/rfc3161#section-2.4.1
type Timestamp struct {
	HashAlgorithm crypto.Hash
	HashedMessage []byte

	Time         time.Time
	Accuracy     time.Duration
	SerialNumber *big.Int

	Certificates []*x509.Certificate

	// Extensions contains raw X.509 extensions from the Extensions field of the
	// timestamp. When parsing time-stamps, this can be used to extract
	// non-critical extensions that are not parsed by this package. When
	// marshaling time-stamps, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// timestamp response. Values override any extensions that would otherwise
	// be produced based on the other fields. The ExtraExtensions field is not
	// populated when parsing timestamp responses, see Extensions.
	ExtraExtensions []pkix.Extension
}

// TSRequest represents an timestamp request. See
// https://tools.ietf.org/html/rfc3161#section-2.4.1
type TSRequest struct {
	HashAlgorithm crypto.Hash
	HashedMessage []byte

	// Certificates indicates if the TSA needs to return the signing certificate
	// and optionally any other certificates of the chain as part of the response.
	Certificates bool

	// Extensions contains raw X.509 extensions from the Extensions field of the
	// timestamp request. When parsing requests, this can be used to extract
	// non-critical extensions that are not parsed by this package. When
	// marshaling OCSP requests, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// OCSP response (in the singleExtensions field). Values override any
	// extensions that would otherwise be produced based on the other fields. The
	// ExtraExtensions field is not populated when parsing timestamp requests,
	// see Extensions.
	ExtraExtensions []pkix.Extension
}

// http://www.ietf.org/rfc/rfc3161.txt
// 2.4.1. Request Format
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      tsaPolicyID      `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	CertReq        bool             `asn1:"optional,default:false"`
	Extensions     []pkix.Extension `asn1:"tag:0,optional"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type tsaPolicyID asn1.ObjectIdentifier

// ParseTSRequest parses an timestamp request in DER form.
func ParseTSRequest(bytes []byte) (*TSRequest, error) {
	var (
		err  error
		rest []byte
		req  timeStampReq
	)

	if rest, err = asn1.Unmarshal(bytes, &req); err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in timestamp request")
	}

	if len(req.MessageImprint.HashedMessage) == 0 {
		return nil, fmt.Errorf("timestamp request contains no hashed message")
	}

	hashFunc, err := getHashForOID(req.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}

	return &TSRequest{
		HashAlgorithm: hashFunc,
		HashedMessage: req.MessageImprint.HashedMessage,
		Certificates:  req.CertReq,
		Extensions:    req.Extensions,
	}, nil
}

// Marshal marshals the timestamp request to ASN.1 DER encoded form.
func (req *TSRequest) Marshal() ([]byte, error) {
	hashOid, err := getDigestOIDForHashAlgorithm(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: hashOid,
				Parameters: asn1.RawValue{
					Tag: 5, /* ASN.1 NULL */
				},
			},
			HashedMessage: req.HashedMessage,
		},
		CertReq:    req.Certificates,
		Extensions: req.ExtraExtensions,
	})
}

// 2.4.2. Response Format
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue
}

type pkiStatusInfo struct {
	Status       int
	StatusString string `asn1:"optional"`
	FailInfo     int    `asn1:"optional"`
}

// ParseTSResponse parses an timestamp response in DER form containing a
// TimeStampToken.
//
// Invalid signatures or parse failures will result in a fmt.Errorf. Error
// responses will result in a ResponseError.
func ParseTSResponse(bytes []byte) (*Timestamp, error) {
	var (
		err  error
		rest []byte
		resp timeStampResp
	)

	if rest, err = asn1.Unmarshal(bytes, &resp); err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in timestamp response")
	}

	if resp.Status.Status > 0 {
		return nil, fmt.Errorf(fmt.Sprintf("%s: %s",
			pkiFailureInfo(resp.Status.FailInfo).String(), resp.Status.StatusString))
	}

	if len(resp.TimeStampToken.Bytes) == 0 {
		return nil, fmt.Errorf("no pkcs7 data in timestamp response")
	}

	return ParseTS(resp.TimeStampToken.FullBytes)
}

// eContent within SignedData is TSTInfo
type tstInfo struct {
	Version        int
	Policy         asn1.RawValue
	MessageImprint messageImprint
	SerialNumber   *big.Int
	Time           time.Time
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

type accuracy struct {
	Seconds      int64 `asn1:"optional"`
	Milliseconds int64 `asn1:"tag:0,optional"`
	Microseconds int64 `asn1:"tag:1,optional"`
}

// ParseTS parses an timestamp in DER form. If the time-stamp contains a
// certificate then the signature over the response is checked.
//
// Invalid signatures or parse failures will result in a fmt.Errorf. Error
// responses will result in a ResponseError.
func ParseTS(bytes []byte) (*Timestamp, error) {
	var inf tstInfo
	p7, err := Parse(bytes)
	if err != nil {
		return nil, err
	}

	if len(p7.Certificates) > 0 {
		if err = p7.Verify(); err != nil {
			return nil, err
		}
	}

	if _, err = asn1.Unmarshal(p7.Content, &inf); err != nil {
		return nil, err
	}

	if len(inf.MessageImprint.HashedMessage) == 0 {
		return nil, fmt.Errorf("timestamp response contains no hashed message")
	}

	ret := &Timestamp{
		HashedMessage: inf.MessageImprint.HashedMessage,
		SerialNumber:  inf.SerialNumber,
		Time:          inf.Time,
		Accuracy: time.Duration((time.Second * time.Duration(inf.Accuracy.Seconds)) +
			(time.Millisecond * time.Duration(inf.Accuracy.Milliseconds)) +
			(time.Microsecond * time.Duration(inf.Accuracy.Microseconds))),
		Certificates: p7.Certificates,

		Extensions: inf.Extensions,
	}

	ret.HashAlgorithm, err = getHashForOID(inf.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// TSRequestOptions contains options for constructing timestamp requests.
type TSRequestOptions struct {
	// Hash contains the hash function that should be used when
	// constructing the timestamp request. If zero, SHA-256 will be used.
	Hash crypto.Hash

	// Certificates sets Request.Certificates
	Certificates bool
}

func (opts *TSRequestOptions) hash() crypto.Hash {
	if opts == nil || opts.Hash == 0 {
		return crypto.SHA256
	}
	return opts.Hash
}

// CreateTSRequest returns a DER-encoded, timestamp request for the status of cert. If
// opts is nil then sensible defaults are used.
func CreateTSRequest(input []byte, opts *TSRequestOptions) ([]byte, error) {
	hashFunc := opts.hash()
	if !hashFunc.Available() {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	h := opts.hash().New()
	h.Write(input)
	req := &TSRequest{
		HashAlgorithm: opts.hash(),
		HashedMessage: h.Sum(nil),
	}
	if opts != nil && opts.Certificates {
		req.Certificates = opts.Certificates
	}
	return req.Marshal()
}

// pkiFailureInfo contains the result of an timestamp request. See
// https://tools.ietf.org/html/rfc3161#section-2.4.2
type pkiFailureInfo int

const (
	// BadAlgorithm defines an unrecognized or unsupported Algorithm Identifier
	BadAlgorithm pkiFailureInfo = 0
	// BadRequest indicates that the transaction not permitted or supported
	BadRequest pkiFailureInfo = 2
	// BadDataFormat means tha data submitted has the wrong format
	BadDataFormat pkiFailureInfo = 5
	// TimeNotAvailable indicates that TSA's time source is not available
	TimeNotAvailable pkiFailureInfo = 14
	// UnacceptedPolicy indicates that the requested TSA policy is not supported
	// by the TSA
	UnacceptedPolicy pkiFailureInfo = 15
	// UnacceptedExtension indicates that the requested extension is not supported
	// by the TSA
	UnacceptedExtension pkiFailureInfo = 16
	// AddInfoNotAvailable means that the information requested could not be
	// understood or is not available
	AddInfoNotAvailable pkiFailureInfo = 17
	// SystemFailure indicates that the request cannot be handled due to system
	// failure
	SystemFailure pkiFailureInfo = 25
)

func (f pkiFailureInfo) String() string {
	switch f {
	case BadAlgorithm:
		return "unrecognized or unsupported Algorithm Identifier"
	case BadRequest:
		return "transaction not permitted or supported"
	case BadDataFormat:
		return "the data submitted has the wrong format"
	case TimeNotAvailable:
		return "the TSA's time source is not available"
	case UnacceptedPolicy:
		return "the requested TSA policy is not supported by the TSA"
	case UnacceptedExtension:
		return "the requested extension is not supported by the TSA"
	case AddInfoNotAvailable:
		return "the additional information requested could not be understood or is not available"
	case SystemFailure:
		return "the request cannot be handled due to system failure"
	default:
		return "unknown failure: " + strconv.Itoa(int(f))
	}
}
