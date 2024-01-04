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
	"embed"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	gjwt "github.com/golang-jwt/jwt/v4"
	. "github.com/smartystreets/goconvey/convey"
)

//go:embed static
var staticFS embed.FS

func TestServer(t *testing.T) {
	username, uid := GetUser(t)
	exampleUser := &User{Username: username, UID: uid}

	Convey("hasError tells you about errors", t, func() {
		So(hasError(nil, nil), ShouldBeFalse)
		So(hasError(nil, ErrBadQuery, nil), ShouldBeTrue)
	})

	Convey("Given a Server", t, func() {
		logWriter := NewStringLogger()
		s := New(logWriter)

		stopCalled := false

		s.SetStopCallBack(func() {
			stopCalled = true
		})

		Convey("Stopping it before starting does nothing", func() {
			s.Stop()
			So(stopCalled, ShouldBeFalse)
		})

		Convey("You can Start the Server", func() {
			certPath, keyPath, err := CreateTestCert(t)
			So(err, ShouldBeNil)

			addr, dfunc, err := StartTestServer(s, certPath, keyPath)
			So(err, ShouldBeNil)
			defer dfunc()

			client := resty.New()
			client.SetRootCertificate(certPath)

			resp, err := client.R().Get("http://" + addr + "/foo")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = client.R().Get("https://" + addr + "/foo")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			router := s.Router()
			So(router, ShouldNotBeNil)

			Convey("The jwt endpoint works after enabling it", func() {
				arouter := s.AuthRouter()
				So(arouter, ShouldBeNil)

				err = s.EnableAuth("/foo", "/bar", func(u, p string) (bool, string) {
					return false, ""
				})
				So(err, ShouldNotBeNil)

				err = s.EnableAuth(certPath, keyPath, func(u, p string) (bool, string) {
					ok := p == "pass"

					return ok, uid
				})
				So(err, ShouldBeNil)

				arouter = s.AuthRouter()
				So(arouter, ShouldNotBeNil)

				r := NewClientRequest(addr, certPath)
				resp, err = r.Post(EndPointJWT)
				So(err, ShouldBeNil)
				So(resp.String(), ShouldEqual, `{"code":401,"message":"missing Username or Password"}`)

				_, err = Login("foo", certPath, username, "foo")
				So(err, ShouldNotBeNil)

				var token string
				token, err = Login(addr, certPath, username, "foo")
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, ErrNoAuth)
				So(token, ShouldBeBlank)

				token, err = Login(addr, certPath, username, "pass")
				So(err, ShouldBeNil)
				So(token, ShouldNotBeBlank)

				var called int
				var claims jwt.MapClaims
				var userI interface{}
				var gu *User

				s.authGroup.GET("/test", func(c *gin.Context) {
					called++
					userI, _ = c.Get(userKey)
					gu = s.GetUser(c)
					claims = jwt.ExtractClaims(c)
				})

				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldEqual, `{"code":401,"message":"auth header is empty"}`)

				r = NewAuthenticatedClientRequest(addr, certPath, "{sdf.sdf.sdf}")
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldEqual, `{"code":401,"message":"illegal base64 data at input byte 0"}`)

				start := time.Now()
				end := start.Add(1 * time.Minute)

				var noClaimToken string
				noClaimToken, err = makeTestToken(keyPath, start, end, false)
				So(err, ShouldBeNil)

				r = NewAuthenticatedClientRequest(addr, certPath, noClaimToken)
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldEqual, `{"code":403,"message":"you don't have permission to access this resource"}`)

				var keyPath2 string
				_, keyPath2, err = CreateTestCert(t)
				So(err, ShouldBeNil)

				var manualWronglySignedToken string
				manualWronglySignedToken, err = makeTestToken(keyPath2, start, end, true)
				So(err, ShouldBeNil)

				r = NewAuthenticatedClientRequest(addr, certPath, manualWronglySignedToken)
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldEqual, `{"code":401,"message":"crypto/rsa: verification error"}`)

				var manualCorrectlySignedToken string
				manualCorrectlySignedToken, err = makeTestToken(keyPath, start, end, true)
				So(err, ShouldBeNil)

				r = NewAuthenticatedClientRequest(addr, certPath, manualCorrectlySignedToken)
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldBeBlank)

				var manualExpiredToken string
				manualExpiredToken, err = makeTestToken(keyPath, start, start.Add(time.Nanosecond), true)
				So(err, ShouldBeNil)

				r = NewAuthenticatedClientRequest(addr, certPath, manualExpiredToken)
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldEqual, `{"code":401,"message":"Token is expired"}`)

				_, err = RefreshJWT("foo", certPath, manualExpiredToken)
				So(err, ShouldNotBeNil)

				_, err = RefreshJWT(addr, certPath, manualWronglySignedToken)
				So(err, ShouldNotBeNil)

				var refreshedToken string
				refreshedToken, err = RefreshJWT(addr, certPath, manualExpiredToken)
				So(err, ShouldBeNil)
				So(refreshedToken, ShouldNotBeBlank)

				r = NewAuthenticatedClientRequest(addr, certPath, refreshedToken)
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldBeBlank)

				past := start.Add(-(2 * tokenDuration) - (2 * time.Nanosecond))
				manualExpiredToken, err = makeTestToken(keyPath, past, past.Add(time.Nanosecond), true)
				So(err, ShouldBeNil)

				_, err = RefreshJWT(addr, certPath, manualExpiredToken)
				So(err, ShouldNotBeNil)

				r = NewAuthenticatedClientRequest(addr, certPath, token)
				resp, err = r.Get(EndPointAuth + "/test")
				So(err, ShouldBeNil)
				So(resp.String(), ShouldBeBlank)

				So(called, ShouldEqual, 3)
				So(claims[userKey], ShouldBeNil)
				So(claims[claimKeyUsername], ShouldEqual, username)
				user, ok := userI.(*User)
				So(ok, ShouldBeTrue)
				So(user, ShouldResemble, exampleUser)
				So(gu, ShouldResemble, exampleUser)
			})

			Convey("authPayLoad correctly maps a User to claims, or returns none", func() {
				data := "foo"
				claims := authPayLoad(data)
				So(len(claims), ShouldEqual, 0)

				claims = authPayLoad(exampleUser)
				So(len(claims), ShouldEqual, 2)
				So(claims, ShouldResemble, jwt.MapClaims{
					claimKeyUsername: username,
					claimKeyUID:      uid,
				})
			})

			Convey("retrieveClaimString fails with bad claims", func() {
				claims := jwt.MapClaims{"foo": []string{"bar"}}

				_, errc := retrieveClaimString(claims, "abc")
				So(errc, ShouldNotBeNil)

				str, errc := retrieveClaimString(claims, "foo")
				So(errc, ShouldNotBeNil)
				So(errc, ShouldEqual, ErrBadJWTClaim)
				So(str, ShouldBeBlank)
			})

			Convey("getUser fails without the user key having a valid value", func() {
				called := 0

				var user1, user2 *User

				s.router.GET("/test", func(c *gin.Context) {
					user1 = s.GetUser(c)
					c.Keys = map[string]interface{}{userKey: "foo"}
					user2 = s.GetUser(c)

					called++
				})

				r := NewClientRequest(addr, certPath)
				resp, err = r.Get("https://" + addr + "/test")
				So(err, ShouldBeNil)

				So(called, ShouldEqual, 1)
				So(user1, ShouldBeNil)
				So(user2, ShouldBeNil)
			})

			Convey("After IncludeAbortErrorsInBody, AbortWithError() calls get their errors in the body", func() {
				router.Use(IncludeAbortErrorsInBody)

				router.GET("/test", func(c *gin.Context) {
					c.AbortWithError(http.StatusUnauthorized, ErrNeedsAuth) //nolint:errcheck
				})

				r := NewClientRequest(addr, certPath)
				resp, err = r.Get("https://" + addr + "/test")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
				So(string(resp.Body()), ShouldEqual, ErrNeedsAuth)
			})

			Convey("Stop() cleans up and calls the callback", func() {
				s.Stop()
				So(stopCalled, ShouldBeTrue)
			})
		})

		Convey("You can add static web pages to the server, with and without GAS_DEV set", func() {
			orig := os.Getenv(DevEnvKey)
			defer func() {
				os.Setenv(DevEnvKey, orig)
			}()

			os.Setenv(DevEnvKey, "0")
			s.AddStaticPage(staticFS, "static", "/s1")

			certPath, keyPath, err := CreateTestCert(t)
			So(err, ShouldBeNil)

			addr, dfunc, err := StartTestServer(s, certPath, keyPath)
			So(err, ShouldBeNil)
			defer dfunc()

			r := NewClientRequest(addr, certPath)
			resp, err := r.Get("https://" + addr + "/s1/index.html")
			So(err, ShouldBeNil)

			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			html := "<!DOCTYPE html>"
			So(resp.String(), ShouldStartWith, html)

			s.AddStaticPage(staticFS, "static/subdir", "/s2/sub")

			resp, err = r.Get("https://" + addr + "/s2/sub/subdir.html")
			So(err, ShouldBeNil)

			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.String(), ShouldStartWith, html)

			os.Setenv(DevEnvKey, "1")
			s.AddStaticPage(staticFS, "static", "/s3")

			resp, err = r.Get("https://" + addr + "/s3/index.html")
			So(err, ShouldBeNil)

			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.String(), ShouldStartWith, html)
		})

		Convey("Endpoints that panic are logged", func() {
			s.router.GET("/foo", func(c *gin.Context) {
				panic("bar")
			})

			response, err := QueryREST(s.router, "/foo", "")
			So(err, ShouldBeNil)
			So(response.Code, ShouldEqual, http.StatusInternalServerError)
			So(logWriter.String(), ShouldContainSubstring, "STATUS=500")
			So(logWriter.String(), ShouldContainSubstring, "panic")

			logWriter.Reset()
			So(logWriter.String(), ShouldBeBlank)
		})
	})
}

func TestServerOktaLogin(t *testing.T) {
	issuer := os.Getenv("OKTA_OAUTH2_ISSUER")
	clientID := os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	secret := os.Getenv("OKTA_OAUTH2_CLIENT_SECRET")
	addr := os.Getenv("OKTA_WRSTAT_ADDR")
	certPath := os.Getenv("OKTA_WRSTAT_CERT")
	keyPath := os.Getenv("OKTA_WRSTAT_KEY")
	username := os.Getenv("OKTA_USERNAME")
	password := os.Getenv("OKTA_PASSWORD")

	if hasBlankValue(issuer, clientID, secret, addr, certPath, keyPath, username, password) {
		SkipConvey("Can't do Okta tests without the OKTA_* env vars set", t, func() {})

		return
	}

	oktaDomain := strings.TrimSuffix(issuer, "oauth2/default")

	Convey("Given a started Server with auth enabled", t, func() {
		logWriter := NewStringLogger()
		s := New(logWriter)

		jwt, err := LoginWithOKTA(addr, certPath, "user", "foo")
		So(err, ShouldNotBeNil)
		So(jwt, ShouldBeBlank)

		dfunc := startTestServerUsingAddress(addr, s, certPath, keyPath)
		defer dfunc()

		err = s.EnableAuth(certPath, keyPath, func(u, p string) (bool, string) {
			return false, ""
		})
		So(err, ShouldBeNil)

		Convey("You can't LoginWithOkta without first getting a code", func() {
			_, err = LoginWithOKTA(addr, certPath, "user", "foo")
			So(err, ShouldNotBeNil)
		})

		Convey("After AddOIDCRoutes you can access the login-cli endpoint and LoginWithOKTA to get a JWT", func() {
			s.AddOIDCRoutes(addr, issuer, clientID, secret)
			r := NewClientRequest(addr, certPath)

			resp, errp := r.Get(EndpointOIDCCLILogin)
			So(errp, ShouldBeNil)
			content := resp.String()
			So(content, ShouldContainSubstring, `ok12static.oktacdn.com`)
			So(content, ShouldContainSubstring, `redirect_uri&#x3d;https&#x25;3A&#x25;2F&#x25;2F`)
			So(content, ShouldContainSubstring, `callback-cli`)

			resp = authnLogin(s, r, oktaDomain, username, password, addr, clientID)

			redirectURL := resp.RawResponse.Request.URL
			So(redirectURL.String(), ShouldContainSubstring, `callback-cli?code=`)

			resp, errp = r.Get(redirectURL.String())
			So(errp, ShouldBeNil)

			code := resp.String()
			So(code, ShouldNotBeBlank)

			jwt, errp := LoginWithOKTA(addr, "", "user", code)
			So(errp, ShouldBeNil)
			So(jwt, ShouldNotBeBlank)
		})

		Convey("After AddOIDCRoutes you can access the login endpoint", func() {
			s.AddOIDCRoutes(addr, issuer, clientID, secret)
			r := NewClientRequest(addr, certPath)

			resp, errp := r.Get(EndpointOIDCLogin)
			So(errp, ShouldBeNil)
			content := resp.String()
			So(content, ShouldContainSubstring, `ok12static.oktacdn.com`)
			So(content, ShouldContainSubstring, `redirect_uri&#x3d;https&#x25;3A&#x25;2F&#x25;2F`)
			So(content, ShouldNotContainSubstring, `callback-cli`)
			So(content, ShouldContainSubstring, `callback`)
		})
	})
}

// ManualOktaAuthn is for testing purposes only.
type ManualOktaAuthn struct {
	SessionToken string `json:"sessionToken" binding:"required"`
}

// hasBlankValue returns true if any of the given values is "".
func hasBlankValue(vals ...string) bool {
	for _, val := range vals {
		if val == "" {
			return true
		}
	}

	return false
}

// makeTestToken creates a JWT signed with the key at the given path, that
// has orig_iat of start and exp of end, and includes a claimKeyUsername claim
// if withUserClaims is true.
func makeTestToken(keyPath string, start, end time.Time, withUserClaims bool) (string, error) {
	token := gjwt.New(gjwt.GetSigningMethod("RS512"))

	claims, ok := token.Claims.(gjwt.MapClaims)
	if !ok {
		return "", ErrNoAuth
	}

	if withUserClaims {
		claims[claimKeyUsername] = "root"
		claims[claimKeyUID] = ""
	}

	claims["orig_iat"] = start.Unix()
	claims["exp"] = end.Unix()

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	key, err := gjwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", err
	}

	return token.SignedString(key)
}

// authnLogin is used to login with username and password via the authn endpoint
// on the given oktaDomain, since we can't use the browser form during this
// test. Also provide a resty.Request from newClientRequest(server_address).
// Returns a resty.Response from trying to authenticate in a similar way as the
// browser would do after submitting the username/password form.
func authnLogin(s *Server, r *resty.Request, oktaDomain, username, password, addr, clientID string) *resty.Response {
	var oauthState, codeChallenge string

	handleOIDCTest := func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")

		o := s.cliOAuth

		session := o.getSession(c)
		if session == nil {
			return
		}

		oauthState = session.Values[oauth2StateKeyCookie].(string) //nolint:errcheck,forcetypeassert
		codeChallenge = o.ccs256
	}

	s.router.GET("/login-test", handleOIDCTest)

	moa := &ManualOktaAuthn{}

	rOkta := resty.New()
	resp, err := rOkta.R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{"username": username, "password": password}).
		SetResult(moa).
		Post(oktaDomain + "api/v1/authn")
	So(err, ShouldBeNil)
	So(resp.String(), ShouldContainSubstring, `"status":"SUCCESS"`)

	sessionToken := moa.SessionToken
	So(sessionToken, ShouldNotBeBlank)

	_, err = r.Get("/login-test")
	So(err, ShouldBeNil)
	So(oauthState, ShouldNotBeBlank)
	So(codeChallenge, ShouldNotBeBlank)

	resp, err = rOkta.R().
		SetQueryParams(map[string]string{
			"client_id":                  clientID,
			"response_type":              oauth2AuthCodeKey,
			"response_mode":              "query",
			"scope":                      "openid email",
			"redirect_uri":               ClientProtocol + addr + EndpointAuthCLICallback,
			"state":                      oauthState,
			"sessionToken":               sessionToken,
			oauth2AuthChallengeKey:       codeChallenge,
			oauth2AuthChallengeMethodKey: oauth2AuthChallengeMethod,
		}).
		SetHeader("Accept", "application/json").
		Get(s.cliOAuth.Endpoint.AuthURL)
	So(err, ShouldBeNil)

	return resp
}
