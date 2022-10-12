# go-authserver
A library to easily create an authenticated web server in Go

Supports arbitrary username&password type authentication using your own callback
to veryify the password, and also Okta auth via both a CLI and a web interface.


The server is gin-based, and you add routes to the server using Router() or
AuthRouter(), then Start() it (it will gracefully stop on SIGINT and SIGTERM):

```
import gas "github.com/wtsi-hgi/go-authserver"

logger := syslog.new(syslog.LOG_INFO, "tag")

server := gas.New(logger)

server.Router().GET(gas.EndPointREST+"/myendpoint", myGinHandlerFunc)

server.EnableAuth("cert.pem", "key.pem", func(username, password string) (bool, string) {
    return true, "" // allows all login attempts; do proper password checking instead!
})

server.AuthRouter().GET("/mysecuredendpoint", myGinHandlerFuncForSecureStuff)

err := server.Start("localhost:8080", "cert.pem", "key.pem")
```

With the server running, a client can login with a username and password:

```
import gas "github.com/wtsi-hgi/go-authserver"

jwt, err := gas.Login("localhost:8080", "cert.pem", "username", "password")

restyRequest := gas.NewAuthenticatedClientRequest("localhost:8080", "cert.pem", jwt)

response, err := restyRequest.Get(gas.EndPointAuth+"/mysecuredendpoint")
```

## Okta

For okta auth, you will need an Okta app configured like:

- Sign-in method: OIDC
- App type: Web application
- Name: [your app name]
- Grant type: Authorization code
- Sign-in redirect URIs: https://[your domain:port]/callback, https://[your domain:port]/callback-cli
- Sign-out redirect URIs: https://[your domain:port]/
- Assignments: allow everyone access

Then for the server, after calling EnableAuth(), also say:

```
server.AddOIDCRoutes(oktaURL, oktaOAuthIssuer, oktaOAuthClientID, oktaOAuthClientSecret)
```

Then a command-line client can log in using Okta after getting a code by
visiting https://localhost:8080/login-cli :

```
jwt, err := gas.LoginWithOKTA("localhost:8080", "cert.pem", code)
```

A web-based client can log in by visiting https://localhost:8080/login .
After logging in they will be redirected to your default route.
