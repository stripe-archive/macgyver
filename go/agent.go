package main

import (
	"errors"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrUnsupported = errors.New("Unsupported operation")

type PlatformKeysAgent struct {
	// chrome.platformKeys
	pk *js.Object
}

// interface agent.Agent

func (a *PlatformKeysAgent) List() ([]*agent.Key, error) {
	_ = a.listCertificates()
	return nil, nil
}

func (a *PlatformKeysAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return nil, nil
}

func (a *PlatformKeysAgent) Signers() ([]ssh.Signer, error) {
	return nil, nil
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

func (a *PlatformKeysAgent) listCertificates() []interface{} {
	certs := make(chan []interface{}, 1)
	req := js.M{
		"request": js.M{
			"certificateTypes":       []string{},
			"certificateAuthorities": js.S{},
		},
		"interactive": false,
	}

	a.pk.Call("selectClientCertificates", req, func(matches []interface{}) {
		certs <- matches
	})

	return <-certs
}

func init() {
	pk := js.Global.Get("chrome").Get("platformKeys")
	js.Global.Set("agent", js.MakeWrapper(&PlatformKeysAgent{pk: pk}))
}
