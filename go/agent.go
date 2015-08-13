package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrUnsupported = errors.New("unsupported operation")
var ErrNotFound = errors.New("not found")

type PKHashAlgorithm struct {
	*js.Object
	Name string `js:"name"`
}

type PKKeyAlgorithm struct {
	*js.Object
	Name string           `js:"name"`
	Hash *PKHashAlgorithm `js:"hash"`
}

type PKMatch struct {
	*js.Object
	Certificate  []byte          `js:"certificate"`
	KeyAlgorithm *PKKeyAlgorithm `js:"keyAlgorithm"`
}

type PlatformKeysAgent struct {
	// chrome.platformKeys
	pk *js.Object
}

func NewPlatformKeysAgent() *PlatformKeysAgent {
	pk := js.Global.Get("chrome").Get("platformKeys")
	return &PlatformKeysAgent{
		pk: pk,
	}
}

func (a *PlatformKeysAgent) List() ([]*agent.Key, error) {
	certs, err := a.listCertificates()
	if err != nil {
		return nil, err
	}

	keys := make([]*agent.Key, 0, len(certs))
	for _, cert := range certs {
		pubkey, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return nil, err
		}

		keys = append(keys, &agent.Key{
			Format:  pubkey.Type(),
			Blob:    pubkey.Marshal(),
			Comment: "",
		})
	}
	return keys, nil
}

func (a *PlatformKeysAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	wanted := key.Marshal()
	signers, err := a.Signers()
	if err != nil {
		return nil, err
	}

	for _, signer := range signers {
		if bytes.Equal(signer.PublicKey().Marshal(), wanted) {
			return signer.Sign(rand.Reader, data)
		}
	}

	return nil, ErrNotFound
}

func algorithm(cert *x509.Certificate) *PKKeyAlgorithm {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return &PKKeyAlgorithm{
			Name: "RSASSA-PKCS1-v1_5",
			Hash: &PKHashAlgorithm{Name: "SHA-1"},
		}
	case x509.ECDSA:
		return &PKKeyAlgorithm{
			Name: "ECDSA",
		}
	default:
		return nil
	}
}

func (a *PlatformKeysAgent) Signers() (signers []ssh.Signer, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	certs, err := a.listCertificates()
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		algo := algorithm(cert)
		res := make(chan *js.Object, 1)
		a.pk.Call("getKeyPair",
			js.NewArrayBuffer(cert.Raw),
			algo,
			func(pubKey *js.Object, privKey *js.Object) {
				go func() { res <- privKey }()
			})

		privkey := <-res
		signer, err := NewPKSigner(a.pk, cert, algo, privkey)
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	return
}

func (a *PlatformKeysAgent) Add(key agent.AddedKey) error {
	return ErrUnsupported
}

func (a *PlatformKeysAgent) Remove(key ssh.PublicKey) error {
	return ErrUnsupported
}

func (a *PlatformKeysAgent) RemoveAll() error {
	return ErrUnsupported
}

func (a *PlatformKeysAgent) Lock(passphrase []byte) error {
	return ErrUnsupported
}

func (a *PlatformKeysAgent) Unlock(passphrase []byte) error {
	return ErrUnsupported
}

func (a *PlatformKeysAgent) listCertificates() (certs []*x509.Certificate, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	results := make(chan []PKMatch, 1)
	req := js.M{
		"request": js.M{
			"certificateTypes":       []string{},
			"certificateAuthorities": js.S{},
		},
		"interactive": false,
	}

	a.pk.Call("selectClientCertificates", req, func(matches []PKMatch) {
		go func() { results <- matches }()
	})

	matches := <-results
	for _, m := range matches {
		cert, err := x509.ParseCertificate(m.Certificate)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return
}
