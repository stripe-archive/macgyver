package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrUnsupported = errors.New("unsupported operation")
var ErrNotFound = errors.New("not found")

// An interface that's a subset of agent.Agent. This abstraction is here so that
// each backend doesn't have to stub out a bunch of methods and can share a bit
// of code.
type Backend interface {
	List() ([]*agent.Key, error)
	Signers() (signers []ssh.Signer, err error)
}

type Agent struct {
	backend Backend
}

func NewAgent(backend Backend) *Agent {
	return &Agent{backend}
}

func (a *Agent) List() ([]*agent.Key, error) {
	return a.backend.List()
}

func (a *Agent) Signers() (signers []ssh.Signer, err error) {
	return a.backend.Signers()
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	wanted := key.Marshal()
	signers, err := a.Signers()
	if err != nil {
		return nil, err
	}

	for _, signer := range signers {
		if bytes.Equal(signer.PublicKey().Marshal(), wanted) {
			log.Printf("Signing message: key=%s", ssh.MarshalAuthorizedKey(signer.PublicKey()))
			return signer.Sign(rand.Reader, data)
		}
	}

	return nil, ErrNotFound
}

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrUnsupported
}

func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrUnsupported
}

func (a *Agent) RemoveAll() error {
	return ErrUnsupported
}

func (a *Agent) Lock(passphrase []byte) error {
	return ErrUnsupported
}

func (a *Agent) Unlock(passphrase []byte) error {
	return ErrUnsupported
}
