package main

import (
	"log"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh/agent"
)

var AllowedClients = map[string]bool{
	// Secure Shell
	"pnhechapfaindjhompbnflcldabbghjo": true,
	// Secure Shell (dev)
	"okddffdblfhhnmhodogpojmfkjmhinfp": true,
}

func main() {
	mga := NewMacGyverAgent()
	js.Global.Set("agent", js.MakeWrapper(mga))

	js.Global.Get("chrome").
		Get("runtime").
		Get("onConnectExternal").
		Call("addListener", func(port *js.Object) {
		go func() {
			sender := port.Get("sender").Get("id").String()
			if !AllowedClients[sender] {
				log.Printf("Received a connection from an unknown extension: %v", sender)
				port.Call("disconnect")
				return
			}

			p := NewAgentPort(port)
			agent.ServeAgent(mga, p)
		}()
	})
}
