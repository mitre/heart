package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"gitlab.mitre.org/andrewg/heart"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v1"
)

func main() {
	// Read in the private key for this RP. The private key
	// must be registered with the OpenID Connect OP.
	jwkJSON, err := os.Open("client_jwk.json")
	if err != nil {
		fmt.Println("Couldn't open the RP JWK file")
		return
	}

	jwkBytes, err := ioutil.ReadAll(jwkJSON)
	if err != nil {
		fmt.Println("Couldn't read the RP JWK file")
		return
	}

	jwk := jose.JsonWebKey{}
	json.Unmarshal(jwkBytes, &jwk)

	g := gin.Default()

	// Set up the HEART Compliant OAuth 2.0 client that will be used by the OIDC RP
	client := heart.Client{
		ISS:         "simple",
		AUD:         "http://localhost:8080/openid-connect-server-webapp/",
		RedirectURI: "http://localhost:3333/redirect",
		PrivateKey:  jwk,
	}

	// Set up the new OpenID Provider
	// This will use discovery to find out the authentication, token and user info endpoints
	provider, err := heart.NewOpenIDProvider("http://localhost:8080/openid-connect-server-webapp")
	if err != nil {
		fmt.Println("Couldn't connect to the OIDC server")
		return
	}

	// Pull down the public key for the provider
	err = provider.FetchKey()
	if err != nil {
		fmt.Println("Couldn't fetch the OIDC server's public key")
		return
	}

	// Set up sessions so we can keep track of the logged in user
	store := sessions.NewCookieStore([]byte("secret"))
	g.Use(sessions.Sessions("mysession", store))

	// The OIDCAuthenticationHandler is set up before the IndexHandler in the handler function
	// chain. It will check to see if the user is logged in based on their session. If they are not
	// the user will be redirected to the authentication endpoint at the OP.
	g.GET("/", heart.OIDCAuthenticationHandler(client, provider), IndexHandler())

	// This handler is to take the redirect from the OP when the user logs in. It will
	// then fetch information about the user by hitting the user info endpoint and put
	// that in the session. Lastly, this handler is set up to redirect the user back
	// to the root.
	g.GET("/redirect", heart.RedirectHandler(client, provider, "http://localhost:3333"))
	g.Run(":3333")
}

// IndexHandler shows the user's name as provided by the user info endpoint.
// It assumes that OIDCAuthenticationHandler will be present in the handler chain
// before it.
func IndexHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ui, _ := c.Get("UserInfo")

		c.String(http.StatusOK, "It worked: %s", ui.(heart.UserInfo).Name)
	}
}
