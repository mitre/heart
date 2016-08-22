package heart

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

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

// OpenIDTokenResponse represents the response from and OpenIDProvider's
// token endpoint when exchanging an authorization code
type OpenIDTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Expiration   time.Time
	IDToken      string `json:"id_token"`
}

type openIDTokenResponse OpenIDTokenResponse

// UnmarshalJSON sets the Expiration to a Time based on the current time
// and the expires_in passed in
func (resp *OpenIDTokenResponse) UnmarshalJSON(data []byte) (err error) {
	o2 := openIDTokenResponse{}
	if err = json.Unmarshal(data, &o2); err == nil {
		*resp = OpenIDTokenResponse(o2)
		now := time.Now()
		resp.Expiration = now.Add(time.Duration(resp.ExpiresIn) * time.Second)
		return
	}
	return
}

// UserInfo represents the information provided by an OpenID Connect
// UserInfo endpoint
type UserInfo struct {
	SUB               string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
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

// AuthURL generates the URL to redirect a client to start the authentication process
// as described here: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func (op *OpenIDProvider) AuthURL(c Client, state string) string {
	values := url.Values{"client_id": {c.ISS}, "state": {state}, "response_type": {"code"},
		"redirect_uri": {c.RedirectURI}, "scope": {"openid profile email"}}
	return fmt.Sprintf("%s?%s", op.Config.AuthorizationEndpoint, values.Encode())
}

// Exchange takes the authorization code and swaps it for the various sets of token that an
// OpenIDProvider can return
func (op *OpenIDProvider) Exchange(code string, c Client) (*OpenIDTokenResponse, error) {
	jwt := NewClientJWT(c.ISS, c.AUD)
	clientAssertion, err := SignJWT(jwt, c.PrivateKey)
	if err != nil {
		return nil, err
	}
	values := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {c.RedirectURI}, "client_assertion": {clientAssertion},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_id":             {c.ISS}}
	resp, err := http.PostForm(op.Config.TokenEndpoint, values)
	if err != nil {
		return nil, errors.Annotate(err, "Couldn't connect to the token endpoint")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Unauthorizedf("Server responded with status code: %d and body:\n %s", resp.StatusCode, string(body))
	}
	decoder := json.NewDecoder(resp.Body)
	token := &OpenIDTokenResponse{}
	err = decoder.Decode(token)
	if err != nil {
		return nil, errors.Annotate(err, "Couldn't decode the token response")
	}
	return token, nil
}

// UserInfo retrieves information about the user from the OpenIDProvider
func (op *OpenIDProvider) UserInfo(accessToken string) (*UserInfo, error) {
	req, _ := http.NewRequest("GET", op.Config.UserInfoEndpoint, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Annotate(err, "Couldn't connect to the user info endpoint")
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	userInfo := &UserInfo{}
	err = decoder.Decode(userInfo)
	if err != nil {
		return nil, errors.Annotate(err, "Couldn't decode the token response")
	}
	return userInfo, nil
}
