/*******************************************************************************
 * Copyright (c) 2022 Genome Research Ltd.
 *
 * Authors:
 *	- Sendu Bala <sb10@sanger.ac.uk>
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

// package server provides a web server for a REST API and website, for end-user
// interaction with the set database (defining sets and getting their status).

package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"gopkg.in/tylerb/graceful.v1"
)

const (
	// EndPointREST is the base location for all REST endpoints.
	EndPointREST = "/rest/v1"

	// EndPointJWT is the endpoint for creating or refreshing a JWT.
	EndPointJWT = EndPointREST + "/jwt"

	// EndPointAuth is the name of the router group that endpoints requiring JWT
	// authorisation should belong to.
	EndPointAuth = EndPointREST + "/auth"

	// EndpointOIDCLogin will be handled by redirecting the user to Okta.
	EndpointOIDCLogin = "/login"

	// EndpointOIDCCLILogin will be handled by redirecting the user to Okta,
	// to get an auth code back to copy paste.
	EndpointOIDCCLILogin = "/login-cli"

	// EndpointAuthCallback is the endpoint where the OIDC provider will
	// send the user back to after login.
	EndpointAuthCallback    = "/callback"
	EndpointAuthCLICallback = "/callback-cli"

	// EndpointCLIAuthCode is the endpoint the user can get an auth code from
	// to copy paste into the terminal for a CLI session.
	EndpointCLIAuthCode = "/auth-code"

	ErrNeedsAuth = Error("authentication must be enabled")

	stopTimeout       = 10 * time.Second
	readHeaderTimeout = 20 * time.Second
)

// AuthCallback is a function that returns true if the given password is valid
// for the given username. It also returns the user's UID.
type AuthCallback func(username, password string) (bool, string)

// StopCallback is a function that you can give SetStopCallback() to have this
// function called when the Server is Stop()ped.
type StopCallback func()

// Server is used to start a web server that provides a REST API for
// authenticating, and a router you can add website pages to.
type Server struct {
	router      *gin.Engine
	srv         *graceful.Server
	srvMutex    sync.Mutex
	authGroup   *gin.RouterGroup
	serverUser  string // the username that started the server
	serverUID   string
	serverToken []byte
	authCB      AuthCallback
	stopCB      StopCallback
	webOAuth    *oauthEnv
	cliOAuth    *oauthEnv
	Logger      *log.Logger
}

// New creates a Server which can serve a REST API and website.
//
// It logs to the given io.Writer, which could for example be syslog using the
// log/syslog pkg with syslog.new(syslog.LOG_INFO, "tag").
func New(logWriter io.Writer) *Server {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	logger := log.New(logWriter, "", 0)

	gin.DisableConsoleColor()
	gin.DefaultWriter = logger.Writer()

	r.Use(ginLogger())

	r.Use(gin.RecoveryWithWriter(logWriter))

	return &Server{
		router: r,
		Logger: logger,
	}
}

// ginLogger returns a handler that will format logs in a way that is searchable
// and nice in syslog output.
func ginLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s %s %s \"%s\"] STATUS=%d %s %s\n",
			param.ClientIP,
			param.Method,
			param.Path,
			param.Request.Proto,
			param.Request.UserAgent(),
			param.StatusCode,
			param.Latency,
			param.ErrorMessage,
		)
	})
}

// Router returns a router for non-authenticed end points. Use it to add end
// points that are sub-paths of EndPointREST (providing the full path to eg.
// GET()).
func (s *Server) Router() *gin.Engine {
	return s.router
}

// AuthRouter returns a router for authenticed end points. Use it to add end
// points that are sub-paths of EndPointAuth (providing just the relative path
// to eg. GET()). This will return nil until you've called EnableAuth().
func (s *Server) AuthRouter() *gin.RouterGroup {
	return s.authGroup
}

// IncludeAbortErrorsInBody is a gin.HandlerFunc that can be Use()d with gin
// routers from Router() and AuthRouter() that ensures that the errors we
// accumulate in AbortWithError() calls get written to the returned body.
func IncludeAbortErrorsInBody(c *gin.Context) {
	c.Next()

	if c.Errors != nil && c.IsAborted() {
		for _, err := range c.Errors {
			c.Writer.Write([]byte(err.Error())) //nolint:errcheck
		}
	}
}

// Start will start listening to the given address (eg. "localhost:8080"), and
// serve the REST API and website over https; you must provide paths to your
// certficate and key file.
//
// It blocks, but will gracefully shut down on SIGINT and SIGTERM. If you
// Start() in a go-routine, you can call Stop() manually.
func (s *Server) Start(addr, certFile, keyFile string) error {
	s.router.Use(secure.New(secure.DefaultConfig()))

	srv := &graceful.Server{
		Timeout: stopTimeout,

		Server: &http.Server{
			Addr:              addr,
			Handler:           s.router,
			ReadHeaderTimeout: readHeaderTimeout,
		},
	}

	s.srvMutex.Lock()
	s.srv = srv
	s.srvMutex.Unlock()

	return srv.ListenAndServeTLS(certFile, keyFile)
}

func (s *Server) SetStopCallBack(cb StopCallback) {
	s.srvMutex.Lock()
	defer s.srvMutex.Unlock()

	s.stopCB = cb
}

// Stop() gracefully stops the server after Start(), and waits for active
// connections to close and the port to be available again. It also calls any
// callback you set with SetStopCallBack().
func (s *Server) Stop() {
	s.srvMutex.Lock()

	if s.srv == nil {
		s.srvMutex.Unlock()

		return
	}

	srv := s.srv
	s.srv = nil
	stopCB := s.stopCB
	s.srvMutex.Unlock()

	ch := srv.StopChan()
	srv.Stop(stopTimeout)
	<-ch

	if stopCB != nil {
		stopCB()
	}
}
