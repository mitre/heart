package heart

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewOpenIDProvider(t *testing.T) {
	assert := assert.New(t)
	g := gin.New()
	g.StaticFile(".well-known/openid-configuration", "fixtures/op_config.json")
	server := httptest.NewServer(g)
	defer server.Close()
	op, err := NewOpenIDProvider(server.URL)
	assert.NoError(err)
	assert.Equal("http://localhost:8080/openid-connect-server-webapp/jwk", op.Config.JWKSURI)
}
