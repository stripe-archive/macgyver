package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/ssh"
)

var ErrUnsupportedAlgorithm = errors.New("Public key is using an unknown algorithm")

type wrappedSSHSigner struct {
	signer crypto.Signer
	pubkey ssh.PublicKey
}

func NewSSHSignerFromSigner(signer crypto.Signer) (ssh.Signer, error) {
	pubkey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return &wrappedSSHSigner{
		signer: signer,
		pubkey: pubkey,
	}, nil
}

func (s *wrappedSSHSigner) PublicKey() ssh.PublicKey {
	return s.pubkey
}

func (s *wrappedSSHSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	// We need to hash the data first, and how we hash depends on
	// the key (logic derived from
	// https://github.com/golang/crypto/blob/master/ssh/keys.go)
	var hashFunc crypto.Hash
	switch k := s.signer.Public().(type) {
	case (*rsa.PublicKey), (*dsa.PublicKey):
		hashFunc = crypto.SHA1
	case (*ecdsa.PublicKey):
		size := k.Params().BitSize
		if size <= 256 {
			hashFunc = crypto.SHA256
		} else if size <= 384 {
			hashFunc = crypto.SHA384
		} else {
			hashFunc = crypto.SHA512
		}
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	hash := hashFunc.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	signature, err := s.signer.Sign(rand, hashed, hashFunc)
	if err != nil {
		return nil, err
	}

	// Ugh, because everything is terrible, ECDSA signatures are
	// encoded in the ssh wire format, not ASN.1, and DSA
	// signatures are encoded by just concatenating the two
	// 0-padded numbers together
	switch s.signer.Public().(type) {
	case (*ecdsa.PublicKey):
		asn1Sig := &struct{ R, S *big.Int }{}
		_, err := asn1.Unmarshal(signature, asn1Sig)
		if err != nil {
			return nil, err
		}

		signature = ssh.Marshal(asn1Sig)
	case (*dsa.PublicKey):
		asn1Sig := &struct{ R, S *big.Int }{}
		_, err := asn1.Unmarshal(signature, asn1Sig)
		if err != nil {
			return nil, err
		}

		signature = make([]byte, 40)
		r := asn1Sig.R.Bytes()
		s := asn1Sig.S.Bytes()
		copy(signature[20-len(r):20], r)
		copy(signature[40-len(s):40], s)
	}

	return &ssh.Signature{
		Format: s.pubkey.Type(),
		Blob:   signature,
	}, nil
}
