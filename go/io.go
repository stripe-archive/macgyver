package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log"

	"github.com/gopherjs/gopherjs/js"
)

var ErrInvalidMsg = errors.New("Invalid message frame")

type AgentPort struct {
	p         *js.Object
	inReader  *io.PipeReader
	inWriter  *io.PipeWriter
	outReader *io.PipeReader
	outWriter *io.PipeWriter
}

func NewAgentPort(p *js.Object) *AgentPort {
	ir, iw := io.Pipe()
	or, ow := io.Pipe()
	ap := &AgentPort{
		p:         p,
		inReader:  ir,
		inWriter:  iw,
		outReader: or,
		outWriter: ow,
	}
	ap.p.Get("onDisconnect").Call("addListener", func() {
		go ap.OnDisconnect()
	})
	ap.p.Get("onMessage").Call("addListener", func(msg js.M) {
		go ap.OnMessage(msg)
	})

	go ap.SendMessages()

	return ap
}

func (ap *AgentPort) OnDisconnect() {
	ap.inWriter.Close()
}

func (ap *AgentPort) OnMessage(msg js.M) {
	d, ok := msg["data"].([]interface{})
	if !ok {
		log.Printf("Message did not contain Array data field: %v", msg)
		ap.p.Call("disconnect")
		return
	}

	framed := make([]byte, 4+len(d))
	binary.BigEndian.PutUint32(framed, uint32(len(d)))

	for i, raw := range d {
		n, ok := raw.(float64)
		if !ok {
			log.Printf("Message contained non-numeric data: %v", msg)
			ap.p.Call("disconnect")
			return
		}

		framed[i+4] = byte(n)
	}

	_, err := ap.inWriter.Write(framed)
	if err != nil {
		log.Printf("Error writing to pipe: %v", err)
		ap.p.Call("disconnect")
	}
}

func (ap *AgentPort) Read(p []byte) (n int, err error) {
	return ap.inReader.Read(p)
}

func (ap *AgentPort) SendMessages() {
	for {
		l := make([]byte, 4)
		_, err := io.ReadFull(ap.outReader, l)
		if err != nil {
			log.Printf("Error reading from pipe: %v", err)
			ap.outReader.Close()
			return
		}
		length := binary.BigEndian.Uint32(l)

		data := make([]byte, length)
		_, err = io.ReadFull(ap.outReader, data)
		if err != nil {
			log.Printf("Error reading from pipe: %v", err)
			ap.outReader.Close()
			return
		}

		encoded := make(js.S, length)
		for i, b := range data {
			encoded[i] = float64(b)
		}

		ap.p.Call("postMessage", js.M{
			"data": encoded,
		})
	}
}

func (ap *AgentPort) Write(p []byte) (n int, err error) {
	return ap.outWriter.Write(p)
}
