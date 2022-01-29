package jwtex

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/pkg/errors"
)

type kmsSigningMethod struct {
	crypto.Signer
}

func (m *kmsSigningMethod) Verify(signingString, signature string, key interface{}) error {
	panic("verify not implemented")
}

func (m *kmsSigningMethod) Sign(signingString string, key interface{}) (string, error) {
	digest := sha256.Sum256([]byte(signingString))

	sig, err := m.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (m *kmsSigningMethod) Alg() string {
	return "RS256"
}
