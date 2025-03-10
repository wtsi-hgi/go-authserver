/*******************************************************************************
 * Copyright (c) 2022 Genome Research Ltd.
 *
 * Authors:
 *	- Sendu Bala <sb10@sanger.ac.uk>
 *	- Michael Grace <mg38@sanger.ac.uk>
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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/mojocn/sseread"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrNoAuth    = Error("authentication failed")
	ErrBadQuery  = Error("bad query")
	ErrGetFailed = Error("GET status not 200")

	ClientProtocol = "https://"
)

// Login is a client call to a Server listening at the domain:port url given to
// the request that checks the given password is valid for the given username,
// and returns a JWT if so.
//
// Make the request using NewClientRequest() and a non-blank path to a
// certificate to force us to trust that certificate, eg. if the server was
// started with a self-signed certificate.
func Login(r *resty.Request, username, password string) (string, error) {
	resp, err := r.SetFormData(map[string]string{
		"username": username,
		"password": password,
	}).
		Post(EndPointJWT)
	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", ErrNoAuth
	}

	return jsonStringBodyToString(resp.Body()), nil
}

// NewClientRequest creates a resty Request that will trust the certificate at
// the given path. cert can be blank to only trust the normal installed cert
// chain.
func NewClientRequest(url, cert string) *resty.Request {
	client := newRestyClient(url, cert)

	return client.R()
}

// newRestyClient creates a Resty client that will trust the certificate at the
// given path. cert can be blank to only trust the normal installed cert chain.
func newRestyClient(url, cert string) *resty.Client {
	client := resty.New()

	if cert != "" {
		client.SetRootCertificate(cert)
	}

	client.SetBaseURL(ClientProtocol + url)

	return client
}

// for testing purposes only, we disable host checking.
func newTestingClientRequest(url, cert string) *resty.Request {
	client := newRestyClient(url, cert)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec

	return client.R()
}

// jsonStringBodyToString takes the response body of a JSON string, and returns
// it as a string.
func jsonStringBodyToString(body []byte) string {
	str := string(body)
	str = strings.TrimPrefix(str, `"`)
	str = strings.TrimSuffix(str, `"`)

	return str
}

// SSERead can be used when testing server SSESender() routes. The returned
// channel will receive the text of any broadcasts to the given url.
func SSERead(url, cert string) (<-chan string, error) {
	config, err := configWithCert(cert)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}

	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrGetFailed
	}

	ch, err := sseread.ReadCh(resp.Body)
	if err != nil {
		return nil, err
	}

	dataCh := make(chan string)

	go func() {
		for event := range ch {
			dataCh <- string(event.Data)
		}
	}()

	return dataCh, nil
}

func configWithCert(cert string) (*tls.Config, error) {
	pemData, err := os.ReadFile(cert)
	if err != nil {
		return nil, err
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(pemData)

	return &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}, nil
}

// LoginWithOKTA sends a request to the server containing the token as a cookie,
// so it will be able to return the JWT for the user. The request should have
// been made with an addr that is just the domain:port that was used to Start()
// the server.
//
// Make the request using NewClientRequest() and a non-blank path to a
// certificate to force us to trust that certificate, eg. if the server was
// started with a self-signed certificate.
func LoginWithOKTA(r *resty.Request, username, token string) (string, error) {
	resp, err := r.SetCookie(&http.Cookie{
		Name:  oktaCookieName,
		Value: token,
	}).SetFormData(map[string]string{
		"username": username,
		"password": token,
	}).
		Post(EndPointJWT)

	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", ErrNoAuth
	}

	return jsonStringBodyToString(resp.Body()), nil
}

// RefreshJWT is like Login(), but refreshes a JWT previously returned by
// Login() if it's still valid.
func RefreshJWT(url, cert, token string) (string, error) {
	r := NewAuthenticatedClientRequest(url, cert, token)

	resp, err := r.Get(EndPointJWT)
	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", ErrNoAuth
	}

	return jsonStringBodyToString(resp.Body()), nil
}

// NewAuthenticatedClientRequest is like NewClientRequest, but sets the given
// JWT in the authorization header.
func NewAuthenticatedClientRequest(url, cert, jwt string) *resty.Request {
	client := newRestyClient(url, cert)

	client.SetAuthToken(jwt)

	return client.R()
}
