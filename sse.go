/*******************************************************************************
 * Copyright (c) 2025 Genome Research Ltd.
 *
 * Author: Sendu Bala <sb10@sanger.ac.uk>
 * This code largely taken from babyapi by CalvinMclean,
 * Apache License, Version 2.0
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

const (
	ErrNoSSESEnder = Error("SSESender has not been called")
	ErrBadSSEEvent = Error("SSESender has not been called with this event name")
)

// sseString is used to give a string the ability to Write() itself to eg. a
// http.ResponseWriter as a server sent event.
type sseString struct {
	data  string
	event string
}

func (sse sseString) Write(w io.Writer) {
	fmt.Fprintf(
		w,
		"event:%s\ndata:%s\n\n",
		sse.event, strings.ReplaceAll(sse.data, "\n", ""),
	)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

type broadcaster struct {
	eventName string
	listeners []chan sseString
	sync.RWMutex
}

// Start begins ranging over the returned channel, calling Broadcast() with the
// the sseString you send on the channel, to replicate the sseString to all
// listeners.
func (bc *broadcaster) Start() chan sseString {
	sseChan := make(chan sseString)

	go func() {
		for input := range sseChan {
			bc.Broadcast(input)
		}
	}()

	return sseChan
}

// Broadcast replicates the given input to all listeners registered with
// NewListener().
func (bc *broadcaster) Broadcast(input sseString) {
	bc.RLock()
	defer bc.RUnlock()

	for _, listener := range bc.listeners {
		listener <- input
	}
}

// NewListener adds a new listener client that will receive future broadcasts
// of new sseString.
func (bc *broadcaster) NewListener() chan sseString {
	bc.Lock()
	defer bc.Unlock()

	newChan := make(chan sseString)
	bc.listeners = append(bc.listeners, newChan)

	return newChan
}

// RemoveListener removes a listener channel previously supplied to
// NewListener().
func (bc *broadcaster) RemoveListener(removeChan chan sseString) {
	bc.Lock()
	defer bc.Unlock()

	for i, listener := range bc.listeners {
		if listener == removeChan {
			bc.listeners[i] = bc.listeners[len(bc.listeners)-1]
			bc.listeners = bc.listeners[:len(bc.listeners)-1]

			close(listener)

			return
		}
	}
}

// SSESender return value can be used as a GET handler for one of your routes,
// to set up an SSE route that will send new strings as an SSE with the given
// event name to clients that connect to it, eg. in an HTMX scenario.
//
// event must be unique for each time you call this. Do not call this
// concurrently.
//
// To actually send new strings to clients, you can call SSEBroadcast(), passing
// it the same event. Eg. in response to a POST request at another route that
// creates a new item that listening clients should be updated about.
func (s *Server) SSESender(event string) func(c *gin.Context) {
	if s.sseChans == nil {
		s.sseChans = make(map[string]chan sseString)
	}

	b := broadcaster{eventName: event}
	s.sseChans[event] = b.Start()

	return func(c *gin.Context) {
		w := c.Writer
		events := b.NewListener()

		defer b.RemoveListener(events)

		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Content-Type", "text/event-stream")

		for {
			select {
			case e := <-events:
				e.Write(w)
			case <-c.Done():
				return
			}
		}
	}
}

// SSEBroadcast, in a goroutine, sends the given string on the channel that
// replicates it to all SSESender(event) listeners.
func (s *Server) SSEBroadcast(event, data string) error {
	if s.sseChans == nil {
		return ErrNoSSESEnder
	}

	sseChan, ok := s.sseChans[event]
	if !ok {
		return ErrBadSSEEvent
	}

	go func() {
		sseChan <- sseString{data: data, event: event}
	}()

	return nil
}
