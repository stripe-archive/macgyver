package main

import (
	"fmt"

	"github.com/gopherjs/gopherjs/js"
)

type PKHashAlgorithm struct {
	*js.Object
	Name string `js:"name"`
}

type PKKeyAlgorithm struct {
	*js.Object
	Name string           `js:"name"`
	Hash *PKHashAlgorithm `js:"hash"`
	// Only for RSA-PSS
	SaltLength int `js:"saltLength"`
	// Only for ECDSA
	NamedCurve string `js:"namedCurve"`
}

type PKMatch struct {
	*js.Object
	Certificate  []byte          `js:"certificate"`
	KeyAlgorithm *PKKeyAlgorithm `js:"keyAlgorithm"`
}

// PlatformKeys is a wrapper for chrome.platformKeys that handles
// making the async API synchronous
type PlatformKeys struct {
	pk *js.Object
}

func (pk *PlatformKeys) SelectClientCertificates(request js.M) (matches []PKMatch, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	results := make(chan []PKMatch, 1)

	pk.pk.Call("selectClientCertificates", request, func(matches []PKMatch) {
		go func() { results <- matches }()
	})

	return <-results, nil
}

type pkKeyPair struct {
	pubkey  *js.Object
	privkey *js.Object
}

func (pk *PlatformKeys) GetKeyPair(rawCert []byte, algorithm *PKKeyAlgorithm) (pubkey *js.Object, privkey *js.Object, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	results := make(chan pkKeyPair, 1)

	pk.pk.Call("getKeyPair", js.NewArrayBuffer(rawCert), algorithm, func(pubkey *js.Object, privkey *js.Object) {
		go func() { results <- pkKeyPair{pubkey, privkey} }()
	})

	pair := <-results
	return pair.pubkey, pair.privkey, nil
}

func (pk *PlatformKeys) Sign(algorithm *PKKeyAlgorithm, privkey *js.Object, data []byte) (sig []byte, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	promise := pk.pk.Call("subtleCrypto").Call("sign", algorithm, privkey, js.NewArrayBuffer(data))

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
		return res, nil
	case err := <-errChan:
		return nil, err
	}
}
