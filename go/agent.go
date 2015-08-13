package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"github.com/gopherjs/gopherjs/js"
	minissh "github.com/stripe/minitrue/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrUnsupported = errors.New("unsupported operation")
var ErrNotFound = errors.New("not found")

type MacGyverAgent struct {
	// chrome.platformKeys
	pk *PlatformKeys
}

func NewMacGyverAgent() *MacGyverAgent {
	pk := js.Global.Get("chrome").Get("platformKeys")
	return &MacGyverAgent{
		pk: &PlatformKeys{pk},
	}
}

func (a *MacGyverAgent) List() ([]*agent.Key, error) {
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

func (a *MacGyverAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
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

func (a *MacGyverAgent) Signers() (signers []ssh.Signer, err error) {
	certs, err := a.listCertificates()
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		signer, err := minissh.NewSignerFromSigner(NewPKSigner(a.pk, cert))
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	return
}

func (a *MacGyverAgent) Add(key agent.AddedKey) error {
	return ErrUnsupported
}

func (a *MacGyverAgent) Remove(key ssh.PublicKey) error {
	return ErrUnsupported
}

func (a *MacGyverAgent) RemoveAll() error {
	return ErrUnsupported
}

func (a *MacGyverAgent) Lock(passphrase []byte) error {
	return ErrUnsupported
}

func (a *MacGyverAgent) Unlock(passphrase []byte) error {
	return ErrUnsupported
}

func (a *MacGyverAgent) listCertificates() ([]*x509.Certificate, error) {
	req := js.M{
		"request": js.M{
			"certificateTypes":       []string{},
			"certificateAuthorities": js.S{},
		},
		"interactive": false,
	}

	matches, err := a.pk.SelectClientCertificates(req)
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, 0, len(matches))
	for _, m := range matches {
		cert, err := x509.ParseCertificate(m)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
