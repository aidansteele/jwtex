package jwtex

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

type oidcDiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	JwksUri                          string   `json:"jwks_uri"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
}

type oidcJwk struct {
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type oidcJwksResponse struct {
	Keys []oidcJwk `json:"keys"`
}

func (srv *Server) handleJwks(w http.ResponseWriter, r *http.Request) {
	pub := srv.signer.Public().(*rsa.PublicKey)

	bigE := big.NewInt(int64(pub.E))

	response := oidcJwksResponse{
		Keys: []oidcJwk{
			{
				Alg: "RS256",
				Kty: "RSA",
				Use: "sig",
				Kid: srv.keyId,
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(bigE.Bytes()),
			},
		},
	}

	j, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (srv *Server) handleDiscoveryDocument(w http.ResponseWriter, r *http.Request) {
	response := oidcDiscoveryDocument{
		Issuer:                           srv.issuer,
		JwksUri:                          fmt.Sprintf("%s/.well-known/jwks", srv.issuer),
		SubjectTypesSupported:            []string{"public"},
		ResponseTypesSupported:           []string{"id_token"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid"},
	}

	j, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}
