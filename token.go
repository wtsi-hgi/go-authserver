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
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
)

const (
	// randBytesToRead is the number of random bytes we read when generating a
	// token.
	randBytesToRead = 32

	// tokenLength is the fixed size of our authentication token.
	tokenLength = 43

	// tokenFilePerms are the self-only perms we create token files with.
	tokenFilePerms = 0600
)

// JWTPermissionsError is used to distinguish this type of error - where the
// already stored JWT token doesn't have private permissions.
type JWTPermissionsError struct {
	tokenFile string
}

// Error is the print out string for JWTPermissionsError, so the user can
// see and rectify the permissions issue.
func (e JWTPermissionsError) Error() string {
	return fmt.Sprintf("Token %s does not have %v permissions "+
		"- won't use it", e.tokenFile, tokenFilePerms)
}

// GenerateAndStoreTokenForSelfClient calls GenerateToken() and returns the
// token, but also stores it in the given file, readable only by the current
// user. You could call this when starting a Server, and then in your
// AuthCallback verify a client trying to login by comparing their "password"
// against the token, using TokenMatches(). (Using EnableAuthWithServerToken()
// does all this for you.)
//
// A command line client started by the same user that started the Server would
// then be able to login by getting the token using GetStoredToken(), and using
// that as its "password".
//
// If the given tokenFile already exists, and contains a single 43 byte string,
// then that is re-used as the token instead.
func GenerateAndStoreTokenForSelfClient(tokenFile string) ([]byte, error) {
	if token, err := GetStoredToken(tokenFile); err == nil && token != nil {
		return token, nil
	}

	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(tokenFile, token, tokenFilePerms)

	return token, err
}

// GetStoredToken reads the token from the given file but only returns it if
// it's got some length.
//
// We also check if the file has private permissions, otherwise we won't use
// it. This is as an attempt to reduce the likelihood of the token being leaked
// with its long expiry time (used so the user doesn't have to continuously log
// in, as we're not working with specific refresh tokens to get new access
// tokens).
func GetStoredToken(tokenFile string) ([]byte, error) {
	stat, err := os.Stat(tokenFile)
	if err != nil {
		return nil, err
	}

	if stat.Mode() != tokenFilePerms {
		return nil, JWTPermissionsError{tokenFile: tokenFile}
	}

	token, err := os.ReadFile(tokenFile)
	if err != nil || len(token) < tokenLength {
		return nil, err
	}

	return token, nil
}

// GenerateToken creates a cryptographically secure pseudorandom URL-safe base64
// encoded string 43 bytes long. Returns it as a byte slice.
func GenerateToken() ([]byte, error) {
	b := make([]byte, randBytesToRead)

	_, err := crand.Read(b)
	if err != nil {
		return nil, err
	}

	token := make([]byte, tokenLength)
	base64.URLEncoding.WithPadding(base64.NoPadding).Encode(token, b)

	return token, err
}

// TokenMatches compares two tokens and tells you if they match. Does so in a
// cryptographically secure way (avoiding timing attacks).
func TokenMatches(input, expected []byte) bool {
	result := subtle.ConstantTimeCompare(input, expected)

	return result == 1
}
