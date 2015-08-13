package main

import (
	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	mga := NewMacGyverAgent()
	js.Global.Set("agent", js.MakeWrapper(mga))

	js.Global.Get("chrome").
		Get("runtime").
		Get("onConnectExternal").
		Call("addListener", func(port *js.Object) {
		p := NewAgentPort(port)
		go func() { agent.ServeAgent(mga, p) }()
	})
}
