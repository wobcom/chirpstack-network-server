package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/brocaar/lorawan"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

// GenerateClientJWT returns a client-certificate for the given gateway ID.
func GenerateClientJWT(gatewayID lorawan.EUI64, jwt_id uuid.UUID) (string, error) {
	if caCert == "" || caKey == "" {
		return "", errors.New("no ca certificate or ca key configured")
	}

	caKeyPair, err := tls.LoadX509KeyPair(caCert, caKey)
	if err != nil {
		return "", errors.Wrap(err, "load ca key-pair error")
	}

	caCert, err := x509.ParseCertificate(caKeyPair.Certificate[0])
	if err != nil {
		return "", errors.Wrap(err, "parse certificate error")
	}

	var method jwt.SigningMethod

	switch caCert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		method = jwt.SigningMethodRS256
	case x509.SHA384WithRSA:
		method = jwt.SigningMethodRS384
	case x509.SHA512WithRSA:
		method = jwt.SigningMethodRS512
	case x509.ECDSAWithSHA256:
		method = jwt.SigningMethodES256
	case x509.ECDSAWithSHA384:
		method = jwt.SigningMethodES384
	case x509.ECDSAWithSHA512:
		method = jwt.SigningMethodES512
	default:
		return "", errors.New("signature algorithm " + caCert.SignatureAlgorithm.String() + "not supported")
	}

	nbf := time.Now()
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss":       "ns",
		"aud":       "jwt-auth",
		"nbf":       nbf.UTC().Unix(),
		"exp":       nbf.UTC().Add(tlsLifetime).Unix(),
		"sub":       "gateway",
		"client_id": gatewayID.String(),
		"jti":       jwt_id.String(),
	})

	key := caKeyPair.PrivateKey
	jwt, err := token.SignedString(key)
	if err != nil {
		return jwt, errors.Wrap(err, "sign jwt token error")
	}

	return jwt, nil
}
