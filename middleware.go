package heart

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v1"
)

// HEARTOAuthIntrospectionHandler creates a gin.HandlerFunc that can be used to introspect
// OAuth 2.0 tokens provided in the request. endpoint is the address of the authorization
// server token introspection service. iss is the client id for the introspection client.
// aud is the audience, which should be the identifier for the authorization server. pk
// is the private key for the client, so it can sign a JWT to authenticate to the introspection
// endpoint.
//
// This middleware will abort any requests that do not have an Authorization header. It will
// also halt requests if the provided bearer token is inactive or expired.
//
// If a valid token is provided, the gin.Context is augmented by setting the following variables:
// scopes will be a []string containing all scopes valid for the provided token. subject will be
// an identifier for the user who delegated the authority represented by the token. clientID will
// contain the identifier for the client issuing the request.
func OAuthIntrospectionHandler(endpoint, iss, aud string, pk jose.JsonWebKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.Request.Header.Get("Authorization")
		if auth == "" {
			c.String(http.StatusForbidden, "No Authorization header provided")
			c.Abort()
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth {
			c.String(http.StatusForbidden, "Could not find bearer token in Authorization header")
			c.Abort()
			return
		}
		jwt := NewClientJWT(iss, aud)
		clientAssertion, err := SignJWT(jwt, pk)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		ir, err := IntrospectToken(endpoint, token, iss, clientAssertion)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		if !ir.Active {
			c.String(http.StatusForbidden, "Provided token is no longer active")
			c.Abort()
			return
		}
		c.Set("scopes", ir.SplitScope())
		c.Set("subject", ir.SUB)
		c.Set("clientID", ir.ClientID)
	}
}
