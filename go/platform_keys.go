package main

import (
	"fmt"

	"github.com/gopherjs/gopherjs/js"
)

// PlatformKeys is a wrapper for chrome.platformKeys that handles
// making the async API synchronous
type PlatformKeys struct {
	pk *js.Object
}

func (pk *PlatformKeys) SelectClientCertificates(request js.M) (matches [][]byte, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	results := make(chan []*js.Object, 1)

	pk.pk.Call("selectClientCertificates", request, func(matches []*js.Object) {
		go func() { results <- matches }()
	})

	objects := <-results
	for _, obj := range objects {
		cert := obj.Get("certificate")
		matches = append(matches, js.Global.Get("Uint8Array").New(cert).Interface().([]byte))
	}

	return
}

type pkKeyPair struct {
	pubkey  *js.Object
	privkey *js.Object
}

func (pk *PlatformKeys) GetKeyPair(rawCert []byte, algorithm js.M) (pubkey *js.Object, privkey *js.Object, err error) {
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

func (pk *PlatformKeys) Sign(algorithm js.M, privkey *js.Object, data []byte) (sig []byte, err error) {
	// Uncaught exceptions in JS get translated into panics in Go
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	promise := pk.pk.Call("subtleCrypto").Call("sign", algorithm, privkey, data)

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
