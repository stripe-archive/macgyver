package main

import (
	"crypto/x509"
	"log"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type PlatformKeysBackend struct {
	pk *PlatformKeys
}

func NewPlatformKeysBackend() *PlatformKeysBackend {
	pk := js.Global.Get("chrome").Get("platformKeys")
	return &PlatformKeysBackend{
		pk: &PlatformKeys{pk},
	}
}

func (a *PlatformKeysBackend) List() ([]*agent.Key, error) {
	certs, err := a.listCertificates()
	if err != nil {
		return nil, err
	}

	log.Printf("Listing keys: count=%d", len(certs))

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

func (a *PlatformKeysBackend) Signers() (signers []ssh.Signer, err error) {
	certs, err := a.listCertificates()
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		signer, err := ssh.NewSignerFromSigner(NewPKSigner(a.pk, cert))
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	return
}

func (a *PlatformKeysBackend) listCertificates() ([]*x509.Certificate, error) {
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
