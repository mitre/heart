package heart

import (
	"encoding/json"
	"net/http"

	"github.com/juju/errors"

	"gopkg.in/square/go-jose.v1"
)

// OPConfig represents the configuration information for an OpenID Connect
// Provider. It is specified here: http://openid.net/specs/openid-connect-discovery-1_0-21.html#ProviderMetadata
type OPConfig struct {
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// OpenIDProvider is a representation of an OpenID Connect Provider. It is
// expected that one will be created using NewOpenIDProvider
type OpenIDProvider struct {
	Config OPConfig
	Key    jose.JsonWebKey
}

// NewOpenIDProvider creates an OpenIDProvider by retrieving its configuration
// information using OpenID Connect Discovery. See http://openid.net/specs/openid-connect-discovery-1_0-21.html
// for details
func NewOpenIDProvider(issuerURL string) (*OpenIDProvider, error) {
	configURL := issuerURL + "/.well-known/openid-configuration"
	resp, err := http.Get(configURL)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to retrieve OpenID Provider Configuration at %s", configURL)
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	config := OPConfig{}
	err = decoder.Decode(&config)
	if err != nil {
		return nil, errors.Annotate(err, "Unable to decode OpenID Provider Configuration")
	}
	return &OpenIDProvider{Config: config}, nil
}

// FetchKey looks at the JWKSURI in the OPConfig, pulls down the
// key set and parses the keys
// TODO: This currently only handles the first key
func (op *OpenIDProvider) FetchKey() error {
	if op.Config.JWKSURI == "" {
		return errors.New("No JWKSURI provided")
	}

	resp, err := http.Get(op.Config.JWKSURI)
	if err != nil {
		return errors.Annotatef(err, "Unable to retrieve JWKS at %s", op.Config.JWKSURI)
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	jwks := &jose.JsonWebKeySet{}
	err = decoder.Decode(jwks)
	if err != nil {
		return errors.Annotate(err, "Unable to decode JWKS")
	}
	op.Key = jwks.Keys[0]

	return nil
}
