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
		go func() {
			p := NewAgentPort(port)
			agent.ServeAgent(mga, p)
		}()
	})
}
