/*******************************************************************************
 * Copyright (c) 2022-2024 Genome Research Ltd.
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
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-resty/resty/v2"
	"golang.org/x/term"
)

const usernameAndPasswordArgLength = 2

// ClientCLI can be used by a CLI client to log in to a go-authserver Server.
type ClientCLI struct {
	jwtBasename, serverTokenBasename, url, cert, user string
	oktaMode                                          bool
	jwt                                               string
}

// NewClientCLI returns a ClientCLI that will get and store JWTs from and to a
// file with the given basename in the user's XDG_STATE_HOME or HOME directory,
// initially retrieving the JWT from the server at url using cert.
//
// If the user needs to login (no valid JWT found), asks user for the password
// or an oktaCode if oktaMode is true.
//
// The normal password checking procedure will be bypassed if the current user
// is the same one that started the server, the server used
// EnableAuthWithServerToken(), and the given serverTokenBasename file in
// XDG_STATE_HOME or HOME contains the server's token.
func NewClientCLI(jwtBasename, serverTokenBasename, url, cert string, oktaMode bool) (*ClientCLI, error) {
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	return &ClientCLI{
		jwtBasename:         jwtBasename,
		serverTokenBasename: serverTokenBasename,
		url:                 url,
		cert:                cert,
		user:                user.Username,
		oktaMode:            oktaMode,
	}, nil
}

// GetJWT checks if we have stored a jwt in our file. If so, the JWT is
// refreshed and returned.
//
// Otherwise, we ask the user for the password/code and login, storing and
// returning the new JWT.
func (c *ClientCLI) GetJWT() (string, error) {
	if c.jwt != "" {
		return c.jwt, nil
	}

	err := c.getStoredJWT()
	if err == nil {
		return c.jwt, nil
	}

	if errors.As(err, &JWTPermissionsError{}) {
		return "", err
	}

	err = c.Login()
	if err == nil {
		err = c.storeJWT(c.jwt)
	}

	return c.jwt, err
}

// getStoredJWT sees if we've previously called storeJWT(), gets the token from
// the file it made, then tries to refresh it on the Server.
func (c *ClientCLI) getStoredJWT() error {
	path, err := c.jwtStoragePath()
	if err != nil {
		return err
	}

	content, err := GetStoredToken(path)
	if err != nil {
		return err
	}

	token := strings.TrimSpace(string(content))

	c.jwt, err = RefreshJWT(c.url, c.cert, token)

	return err
}

// jwtStoragePath returns the path where we store our JWT.
func (c *ClientCLI) jwtStoragePath() (string, error) {
	dir, err := TokenDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, c.jwtBasename), nil
}

// TokenDir is the directory where the server will store a token file when using
// GenerateAndStoreTokenForSelfClient(), and ClientCLI will store JWTs. It is
// the value of XDG_STATE_HOME, falling back to the user's HOME directory.
func TokenDir() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		var err error

		dir, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}

	return dir, nil
}

// Login either asks the user for a password or for their okta code and logs in
// to our server with it. If this user started the server, gets the "password"
// from the server token file instead. If the optional username and password are
// supplied (for testing purposes), uses those instead of asking on the
// terminal.
func (c *ClientCLI) Login(usernameAndPassword ...string) error {
	user, passwordB, err := c.getUsernameAndPassword(usernameAndPassword...)
	if err != nil {
		return err
	}

	r := NewClientRequest(c.url, c.cert)

	if c.oktaMode {
		c.jwt, err = LoginWithOKTA(r, user, string(passwordB))
	} else {
		c.jwt, err = Login(r, user, string(passwordB))
	}

	return err
}

func (c *ClientCLI) getUsernameAndPassword(usernameAndPassword ...string) (string, []byte, error) {
	passwordB, err := c.getPasswordFromServerTokenFile()
	if err == nil && passwordB != nil {
		return c.user, passwordB, nil
	}

	if len(usernameAndPassword) == usernameAndPasswordArgLength {
		return usernameAndPassword[0], []byte(usernameAndPassword[1]), nil
	}

	passwordB, err = c.askForPasswordOrCode()

	return c.user, passwordB, err
}

func (c *ClientCLI) getPasswordFromServerTokenFile() ([]byte, error) {
	tokenPath, err := c.tokenStoragePath()
	if err != nil {
		return nil, err
	}

	return GetStoredToken(tokenPath)
}

func (c *ClientCLI) askForPasswordOrCode() ([]byte, error) {
	if c.oktaMode {
		cliPrint("Login at this URL, and then copy and paste the given code back here: https://%s%s\n",
			c.url, EndpointOIDCCLILogin)
		cliPrint("Auth Code:")
	} else {
		cliPrint("Password: ")
	}

	answer, err := term.ReadPassword(syscall.Stdin)

	cliPrint("\n")

	return answer, err
}

// cliPrint outputs the message to STDOUT.
func cliPrint(msg string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, msg, a...)
}

// tokenStoragePath returns the path where we store our server token.
func (c *ClientCLI) tokenStoragePath() (string, error) {
	dir, err := TokenDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, c.serverTokenBasename), nil
}

// storeJWT writes the given token string to a private file in user's home dir.
func (c *ClientCLI) storeJWT(token string) error {
	path, err := c.jwtStoragePath()
	if err != nil {
		return err
	}

	return os.WriteFile(path, []byte(token), tokenFilePerms)
}

// CanReadServerToken returns true if this user can read the server token file
// and the token is the correct length. Does NOT check with the server if it's
// actually correct. Use this as a shortcut prior to trying to login for a CLI
// command that's only intended for use by the user who started a server.
func (c *ClientCLI) CanReadServerToken() bool {
	_, err := c.getPasswordFromServerTokenFile()

	return err == nil
}

// NewAuthenticatedRequest logs in to our server if needed to get the jwt, and
// returns an authenticated request.
func (c *ClientCLI) AuthenticatedRequest() (*resty.Request, error) {
	jwt, err := c.GetJWT()
	if err != nil {
		return nil, err
	}

	return NewAuthenticatedClientRequest(c.url, c.cert, jwt), nil
}
