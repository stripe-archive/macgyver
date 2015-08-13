package main

import (
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"strings"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
)

type PKSigner struct {
	pk         *PlatformKeys
	publicKey  ssh.PublicKey
	algo       *PKKeyAlgorithm
	privateKey *js.Object
}

func NewPKSigner(pk *PlatformKeys, cert *x509.Certificate, algo *PKKeyAlgorithm, privkey *js.Object) (ssh.Signer, error) {
	pubkey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &PKSigner{
		pk:         pk,
		publicKey:  pubkey,
		algo:       algo,
		privateKey: privkey,
	}, nil
}

func (pks *PKSigner) PublicKey() ssh.PublicKey {
	return pks.publicKey
}

func (pks *PKSigner) Sign(rand io.Reader, data []byte) (sig *ssh.Signature, err error) {
	res, err := pks.pk.Sign(pks.algo, pks.privateKey, data)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(pks.publicKey.Type(), "ecdsa-") {
		// Ugh, because everything is terrible, ECDSA signatures are
		// encoded in the ssh wire format, not ASN.1
		asn1Sig := &struct{ R, S *big.Int }{}
		_, err := asn1.Unmarshal(res, asn1Sig)
		if err != nil {
			return nil, err
		}

		res = ssh.Marshal(asn1Sig)
	}

	return &ssh.Signature{
		Format: pks.publicKey.Type(),
		Blob:   res,
	}, nil
}
