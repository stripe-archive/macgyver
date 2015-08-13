package main

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
)

type PKSigner struct {
	pk         *js.Object
	publicKey  ssh.PublicKey
	algo       *PKKeyAlgorithm
	privateKey *js.Object
}

func NewPKSigner(pk *js.Object, cert *x509.Certificate, algo *PKKeyAlgorithm, privkey *js.Object) (ssh.Signer, error) {
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
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	crypto := pks.pk.Call("subtleCrypto")
	promise := crypto.Call("sign", pks.algo, pks.privateKey, js.NewArrayBuffer(data))

	errChan := make(chan error, 1)
	resChan := make(chan []byte, 1)

	promise.Call("then", func(result *js.Object) {
		go func() { resChan <- js.Global.Get("Uint8Array").New(result).Interface().([]byte) }()
	})
	promise.Call("catch", func(err interface{}) {
		go func() { errChan <- fmt.Errorf("%s", err) }()
	})

	var res []byte
	select {
	case res = <-resChan:
		break
	case err := <-errChan:
		return nil, err
	}

	if strings.HasPrefix(pks.publicKey.Type(), "ecdsa-") {
		// Ugh, because everything is terrible, ECDSA signatures are
		// encoded in the ssh wire format, not ASN.1, and DSA
		// signatures are encoded by just concatenating the two
		// 0-padded numbers together
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
