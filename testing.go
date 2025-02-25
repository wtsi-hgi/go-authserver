/*******************************************************************************
 * Copyright (c) 2022 Genome Research Ltd.
 *
 * Author: Sendu Bala <sb10@sanger.ac.uk>
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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

const (
	minNumPortsForChecker   = 2
	waitAfterStartingServer = 100 * time.Millisecond
)

// CreateTestCert creates a self-signed cert and key in a temp dir and returns
// their paths.
func CreateTestCert(t *testing.T) (string, string, error) {
	t.Helper()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert")
	keyPath := filepath.Join(dir, "key")

	cmd := exec.Command("openssl", "req", "-new", "-newkey", "rsa:4096",
		"-days", "1", "-nodes", "-x509", "-subj", "/CN=localhost",
		"-addext", "subjectAltName = DNS:localhost",
		"-keyout", keyPath, "-out", certPath,
	)

	err := cmd.Run()

	return certPath, keyPath, err
}

// StartStop is an interface that Server satisfies.
type StartStop interface {
	Start(addr, certFile, keyFile string) error
	Stop()
}

// StartTestServer starts the given server using the given cert and key paths
// and returns the address and a func you should defer to stop the server.
func StartTestServer(s StartStop, certPath, keyPath string) (string, func() error, error) {
	addr, err := getTestServerAddress()
	if err != nil {
		return "", nil, err
	}

	dfunc := startTestServerUsingAddress(addr, s, certPath, keyPath)

	return addr, dfunc, nil
}

// getTestServerAddress determines a free port and returns localhost:port.
func getTestServerAddress() (string, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", err
	}

	defer l.Close()

	return fmt.Sprintf("localhost:%d", l.Addr().(*net.TCPAddr).Port), nil
}

// startTestServerUsingAddress does the main work of StartTestServer().
func startTestServerUsingAddress(addr string, s StartStop, certPath, keyPath string) func() error {
	var g errgroup.Group

	g.Go(func() error {
		return s.Start(addr, certPath, keyPath)
	})

	<-time.After(waitAfterStartingServer)

	return func() error {
		s.Stop()

		return g.Wait()
	}
}

// QueryREST does a test GET of the given REST endpoint (start it with /), with
// extra appended (start it with ?). router can be Server.Router().
func QueryREST(router *gin.Engine, endpoint, extra string) (*httptest.ResponseRecorder, error) {
	response := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint+extra, nil)
	if err != nil {
		return nil, err
	}

	router.ServeHTTP(response, req)

	return response, nil
}

// GetUser returns the current user's username and uid.
func GetUser(t *testing.T) (string, string) {
	t.Helper()

	uu, err := user.Current()
	if err != nil {
		t.Logf("getting current user failed: %s", err.Error())

		return "", ""
	}

	return uu.Username, uu.Uid
}
