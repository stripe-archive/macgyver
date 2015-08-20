package main

import (
	"log"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	if (true) { // Set to false for debugging localStorage backend
		launch(NewPlatformKeysAgent())
	} else {
		a, err := NewChromeStorageAgent()
		if err != nil {
			log.Printf("Failed to create ChromeStorageAgent: %v", err)
			return
		}
		launch(a)
	}
}

func launch(mga agent.Agent) {
	js.Global.Set("agent", js.MakeWrapper(mga))

	js.Global.Get("chrome").
		Get("runtime").
		Get("onConnectExternal").
		Call("addListener", func(port *js.Object) {
		p := NewAgentPort(port)
		go func() { agent.ServeAgent(mga, p) }()
	})
}
