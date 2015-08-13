package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh/agent"
)

var k = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDxJveJPA5r8E3xWoHJSGzt37qfslwLgdUty7Awqa5PxRxkGts1
ijIywziPKlnKo9HBj3DtHfK7szoFq3MgsOuXYkdOR224tjaXxCZqBSV3ST3gICIr
VVl97f+NqSg9cSfxlROwZlil0wSgBD7tatBrrfpYO3uPUajqMjqr9IiXOwIDAQAB
AoGBAJKrlJqPQGY9/enxlkaKGlaDYMqIfJszGCmGXV77lN1HkYEBJJpntyhQvDG3
HG23PXhwecp+EIhA9eVE5fzYHjECZIbLvLIEcUjelvYIYlXVkuBzDpTnIMSn1U8h
Pe6KcIraOLYPkknDK/FNJGAKKE3KazEU4FBHWXW+N8A9KqXBAkEA/5zIbIHJgbcx
dnhFtMTwrpmHoGq84IL26AMdwiHjIhU36/WvQkgxF+nElLgNGU4kBpKpmmQb5bKK
9geQ32r2WQJBAPGEkjxrCW1amm3YWKyZ+tn9HfcAQzwnwqVT+CU2mY4YrU/L0hM8
MoTCgasKJOTqWZ6PtdJu1y2GVM6fX30kL7MCQQC4ZrPUS6FCWhVt4QBwk68KVqoY
WUhfMzvKTw010tqX6PTJ3hkMWSZJmRR/MXQJsGye7Uk7n0Lc53wGV5j1BKYpAkA4
Jd3pdejnJ10nlFhpKBMNgq7osYLwBT5XOUJDRIJGaq5AEt5v4lrMSnviy6TwIxta
pYZbubEEwGoO7zY/3Z3JAkEA0OzujATYs7BaYlfLJgt5teQgHDb2OjtGTphk4zAu
N25nKkaa7VoB031y5r2fLrPyajCl1VfPWXN8cP4QlYvUZw==
-----END RSA PRIVATE KEY-----`

func main() {
	a := agent.NewKeyring()
	js.Global.Set("agent", a)

	blk, _ := pem.Decode([]byte(k))
	key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		log.Printf("Error! %v", err)
	}

	err = a.Add(agent.AddedKey{PrivateKey: key})
	if err != nil {
		log.Printf("Error! %v", err)
	}

	log.Printf("Keys loaded!")

	js.Global.Get("chrome").
		Get("runtime").
		Get("onConnectExternal").
		Call("addListener", func(port *js.Object) {
		go func() {
			p := NewAgentPort(port)
			agent.ServeAgent(a, p)
		}()
	})
}
