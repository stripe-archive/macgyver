package main

import (
	"errors"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ChromeStorageBackend struct {
	signer ssh.Signer
}

func NewChromeStorageBackend() (*ChromeStorageBackend, error) {
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
	agent := &ChromeStorageBackend{signer}
	return agent, nil
}

func (a *ChromeStorageBackend) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, 1)
	pubkey := a.signer.PublicKey()
	keys = append(keys, &agent.Key{
		Format:  pubkey.Type(),
		Blob:    pubkey.Marshal(),
		Comment: "",
	})
	return keys, nil
}

func (a *ChromeStorageBackend) Signers() (signers []ssh.Signer, err error) {
	return []ssh.Signer{a.signer}, nil
}
