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

## Server token file

The server can generate a short-lived server token file that allows the user
who started the server to login as an administrative "self-client" without
providing a normal password. This is enabled with `EnableAuthWithServerToken()`
on the server side.

By default `EnableAuthWithServerToken(certFile, keyFile, tokenBasename, acb)`
will store the token in `TokenDir()/tokenBasename` (where `TokenDir()` is
`$XDG_STATE_HOME` or the user's home directory). For flexibility, the
`tokenBasename` argument may instead be an absolute path — if it is absolute
the path will be used directly. The client constructor `NewClientCLI(...,
serverTokenBasename, ...)` accepts the same form: pass an absolute path to
point the client at a token file stored in a non-standard location.

Security note: token files must be private (file mode `0600`) — the client and
server will refuse to use token files with looser permissions and return an
error (see `GetStoredToken()` and `JWTPermissionsError`). Always keep shared
token files on secure storage and remove them when no longer needed.

````
