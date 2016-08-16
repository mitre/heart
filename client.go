package heart

import (
	"encoding/json"
	"time"

	"github.com/icrowley/fake"
	"github.com/juju/errors"

	"gopkg.in/square/go-jose.v1"
)

// ClientJWT represents the JWT used to authenticate a client to a token
// endpoint as specified in Health Relationship Trust Profile for OAuth 2.0 -
// Section 2.2: http://openid.bitbucket.org/HEART/openid-heart-oauth2.html#rfc.section.2.2
type ClientJWT struct {
	ISS string `json:"iss"`
	SUB string `json:"sub"`
	AUD string `json:"aud"`
	IAT int64  `json:"iat"`
	EXP int64  `json:"exp"`
	JTI string `json:"jti"`
}

// NewClientJWT creates a ClientJWT. ISS and SUB are set to the same thing.
// IAT is set to the current time and EXP is set 60 seconds later.
func NewClientJWT(iss string, aud string) ClientJWT {
	jwt := ClientJWT{}
	jwt.ISS = iss
	jwt.SUB = iss
	jwt.AUD = aud
	now := time.Now()
	jwt.IAT = now.Unix()
	jwt.EXP = jwt.IAT + 60
	jwt.JTI = fake.CharactersN(50)
	return jwt
}

// SignJWT takes a ClientJWT, marshals it into JSON, signs the JSON with the
// JWK provided and then returns the blob as a string.
func SignJWT(jwt ClientJWT, pk jose.JsonWebKey) (string, error) {
	signer, err := jose.NewSigner(jose.RS512, pk.Key)
	if err != nil {
		return "", errors.Annotate(err, "Couldn't create JWT Signer")
	}
	json, err := json.Marshal(jwt)
	if err != nil {
		return "", errors.Annotate(err, "Couldn't marshal the JWT")
	}
	jws, err := signer.Sign(json)
	if err != nil {
		return "", errors.Annotate(err, "Couldn't sign the JWT")
	}
	return jws.CompactSerialize()
}
