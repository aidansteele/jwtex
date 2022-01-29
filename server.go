package jwtex

import (
	"crypto"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/coreos/go-oidc/v3/oidc"
	"io/ioutil"
	"net/http"
)

type Server struct {
	issuer    string
	keyId     string
	signer    crypto.Signer
	verifiers map[string]*oidc.IDTokenVerifier
	mapperArn string
	lambda    lambdaiface.LambdaAPI
}

func NewServer(issuer string, keyId string, signer crypto.Signer, verifiers map[string]*oidc.IDTokenVerifier, mapperArn string, lambda lambdaiface.LambdaAPI) *Server {
	return &Server{issuer: issuer, keyId: keyId, signer: signer, verifiers: verifiers, mapperArn: mapperArn, lambda: lambda}
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc("/exchange", srv.handleExchange)
	mux.HandleFunc("/.well-known/openid-configuration", srv.handleDiscoveryDocument)
	mux.HandleFunc("/.well-known/jwks", srv.handleJwks)
	mux.ServeHTTP(w, r)
}

func (srv *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	inputJwt, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unable to read request body", 400)
		panic(err)
	}

	input := ExchangeInput{
		Jwt:      string(inputJwt),
		IssuerId: r.URL.Query().Get("issuerId"),
	}

	output, err := srv.exchange(r.Context(), &input)
	if err != nil {
		http.Error(w, "unable to exchange", 400)
		panic(err)
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(output.Jwt))
}
