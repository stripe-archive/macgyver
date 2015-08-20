package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ChromeStorageAgent struct {
	signer ssh.Signer
}

func NewChromeStorageAgent() (*ChromeStorageAgent, error) {
	storage := js.Global.Get("window").Get("localStorage")
	rawPemStr := storage.Get("privateKey").String()
	if rawPemStr == "undefined" {
		return nil, errors.New("No key stored in local storage.")
	}
	rawPem := []byte(rawPemStr)
	signer, err := ssh.ParsePrivateKey(rawPem)
	if err != nil {
		return nil, err
	}
	agent := &ChromeStorageAgent{signer}
	return agent, nil
}

func (a *ChromeStorageAgent) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, 1)
	pubkey := a.signer.PublicKey()
	keys = append(keys, &agent.Key{
		Format:  pubkey.Type(),
		Blob:    pubkey.Marshal(),
		Comment: "",
	})
	return keys, nil
}

func (a *ChromeStorageAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	wanted := key.Marshal()
	if bytes.Equal(a.signer.PublicKey().Marshal(), wanted) {
		log.Printf("Signing message: key=%s", ssh.MarshalAuthorizedKey(a.signer.PublicKey()))
		return a.signer.Sign(rand.Reader, data)
	}
	return nil, ErrNotFound
}

func (a *ChromeStorageAgent) Signers() (signers []ssh.Signer, err error) {
	return nil, ErrUnsupported
}

func (a *ChromeStorageAgent) Add(key agent.AddedKey) error {
	return ErrUnsupported
}

func (a *ChromeStorageAgent) Remove(key ssh.PublicKey) error {
	return ErrUnsupported
}

func (a *ChromeStorageAgent) RemoveAll() error {
	return ErrUnsupported
}

func (a *ChromeStorageAgent) Lock(passphrase []byte) error {
	return ErrUnsupported
}

func (a *ChromeStorageAgent) Unlock(passphrase []byte) error {
	return ErrUnsupported
}
