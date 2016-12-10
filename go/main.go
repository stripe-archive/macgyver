package main

import (
	"log"

	"github.com/gopherjs/gopherjs/js"
	"golang.org/x/crypto/ssh/agent"
)

func platformKeysSupported() bool {
	return js.Undefined != js.Global.Get("chrome").Get("platformKeys")
}

func main() {
	var backend Backend
	if platformKeysSupported() {
		backend = NewPlatformKeysBackend()
	} else {
		var err error
		backend, err = NewChromeStorageBackend()
		if err != nil {
			log.Printf("Failed to create ChromeStorageAgent: %v", err)
			return
		}
	}
	launch(NewAgent(backend))
}

func isBackgroundPage() bool {
	bg := js.Global.Get("chrome").
		Get("extension").
		Call("getBackgroundPage")
	return js.Global == bg
}

func isOptionsPage() bool {
	path := js.Global.Get("location").
		Get("pathname").
		String()
	return path == "/html/options.html"
}

func launch(mga *Agent) {
	js.Global.Set("agent", js.MakeWrapper(mga))

	if isBackgroundPage() {
		log.Printf("Starting agent")
		js.Global.Get("chrome").
			Get("runtime").
			Get("onConnectExternal").
			Call("addListener", func(port *js.Object) {
				p := NewAgentPort(port)
				go agent.ServeAgent(mga, p)
			})
	} else if isOptionsPage() {
		js.Global.Get("document").
			Call("addEventListener", "DOMContentLoaded", func() {
				go func() {
					textarea := js.Global.Get("document").
						Call("getElementById", "keys")
					textarea.Set("textContent", mga.PubKeys())
					textarea.Get("style").Set("height",
						textarea.Get("scrollHeight").String()+"px")
					textarea.Call("addEventListener", "click", func() {
						textarea.Call("focus")
						textarea.Call("select")
					})
				}()
			})
	}
}
