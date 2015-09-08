package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"

	"github.com/gopherjs/gopherjs/js"
)

var ErrUnsupportedHash = errors.New("unsupported hash")

type PKSigner struct {
	pk   *PlatformKeys
	cert *x509.Certificate
}

func NewPKSigner(pk *PlatformKeys, cert *x509.Certificate) crypto.Signer {
	return &PKSigner{
		pk:   pk,
		cert: cert,
	}
}

func (pks *PKSigner) Public() crypto.PublicKey {
	return pks.cert.PublicKey
}

// Limited to just the hashes supported by WebCrypto
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA1:    {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA256:  {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:  {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:  {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.Hash(0): {}, // Special case in the golang interface to indicate that data is signed directly
}

var hashNames = map[crypto.Hash]string{
	crypto.SHA1:    "SHA-1",
	crypto.SHA256:  "SHA-256",
	crypto.SHA384:  "SHA-384",
	crypto.SHA512:  "SHA-512",
	crypto.Hash(0): "none",
}

var curveNames = map[elliptic.Curve]string{
	elliptic.P256(): "P-256",
	elliptic.P384(): "P-384",
	elliptic.P521(): "P-521",
}

func (pks *PKSigner) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// RSA is kind of a small disaster because of the way that the
	// crypto.Signer interface is laid out.
	//
	// For PKCS1v1.5 RSA signatures, the input to the actual
	// signature function is an ASN.1 DER-encoded
	// structure. WebCrypto has hash-specific mechanisms which
	// know how to generate that structure, but they all assume
	// the data is un-hashed, which is not the case with the
	// crypto.Signer interface, so we have to ues {hash: {name:
	// 'none'}}, which just performs the raw signature operation.
	//
	// This means we have to generate the ASN.1 structure
	// ourselves, which we can do by just having the correct
	// prefixes for all the hashes we might want to use. Prefixes
	// are taken from src/crypto/rsa/pkcs1v15.go. No other
	// signatures require this song and dance

	hash := hashNames[opts.HashFunc()]

	var algorithm js.M
	switch k := pks.Public().(type) {
	case *rsa.PublicKey:
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			algorithm = js.M{
				"name":       "RSA-PSS",
				"saltLength": pssOpts.SaltLength,
				"hash":       js.M{"name": hash},
			}
		} else {
			algorithm = js.M{
				"name": "RSASSA-PKCS1-v1_5",
				"hash": js.M{"name": "none"},
			}

			prefix, ok := hashPrefixes[opts.HashFunc()]
			if !ok {
				return nil, ErrUnsupportedHash
			}

			msg = append(prefix, msg...)
		}
	case *ecdsa.PublicKey:
		curveName, ok := curveNames[k.Curve]
		if !ok {
			return nil, ErrUnsupported
		}

		algorithm = js.M{
			"name":       "ECDSA",
			"hash":       js.M{"name": hash},
			"namedCurve": curveName,
		}
	}

	_, privkey, err := pks.pk.GetKeyPair(pks.cert.Raw, algorithm)
	if err != nil {
		return nil, err
	}

	return pks.pk.Sign(algorithm, privkey, msg)
}
