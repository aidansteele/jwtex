package jwtex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"os"
	"strings"
	"time"
)

type ExchangeInput struct {
	IssuerId string
	Jwt      string
}

type ExchangeOutput struct {
	Allowed bool
	Jwt     string
}

type auditLogEntry struct {
	AuditTimestamp time.Time
	XrayTraceId    string
	IssuerId       string
	Allowed        bool
	OutputSize     int `json:"OutputSize,omitempty"`
	SrcHeader      json.RawMessage
	SrcClaims      json.RawMessage
	DstHeader      json.RawMessage
	DstClaims      json.RawMessage
}

func writeAuditEntry(ctx context.Context, input *ExchangeInput, output *ExchangeOutput) {
	parse := func(jwt string) (json.RawMessage, json.RawMessage) {
		split := strings.Split(jwt, ".")
		if len(split) != 3 {
			return nil, nil
		}

		hdr, _ := base64.RawURLEncoding.DecodeString(split[0])
		claims, _ := base64.RawURLEncoding.DecodeString(split[1])
		return hdr, claims
	}

	e := auditLogEntry{
		AuditTimestamp: time.Now(),
		XrayTraceId:    os.Getenv("_X_AMZN_TRACE_ID"),
		IssuerId:       input.IssuerId,
		Allowed:        output.Allowed,
		OutputSize:     len(output.Jwt),
	}

	e.SrcHeader, e.SrcClaims = parse(input.Jwt)
	e.DstHeader, e.DstClaims = parse(output.Jwt)

	j, _ := json.Marshal(e)
	fmt.Println(string(j))
}

func (srv *Server) exchange(ctx context.Context, input *ExchangeInput) (output *ExchangeOutput, err error) {
	output = &ExchangeOutput{}
	defer writeAuditEntry(ctx, input, output)

	verifier := srv.verifiers[input.IssuerId]
	if verifier == nil {
		return nil, errors.Errorf("unrecognised issuerId: %s", input.IssuerId)
	}

	inputToken, err := verifier.Verify(ctx, input.Jwt)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	inputClaims := map[string]interface{}{}
	err = inputToken.Claims(&inputClaims)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	j, _ := json.Marshal(&ClaimsMapperInput{
		Version:  ClaimsMapperVersion,
		IssuerId: input.IssuerId,
		Claims:   inputClaims,
	})

	invoke, err := srv.lambda.InvokeWithContext(ctx, &lambda.InvokeInput{FunctionName: &srv.mapperArn, Payload: j})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	mapperOutput := ClaimsMapperOutput{}
	err = json.Unmarshal(invoke.Payload, &mapperOutput)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !mapperOutput.Allow {
		return nil, errors.New("disallowed by mapper")
	}

	// TODO: should we be doing this?
	mapperOutput.Claims["iss"] = srv.issuer

	outputToken := jwt.NewWithClaims(&kmsSigningMethod{Signer: srv.signer}, jwt.MapClaims(mapperOutput.Claims))
	outputToken.Header["kid"] = srv.keyId

	signedJwt, err := outputToken.SignedString(nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	output.Jwt = signedJwt
	output.Allowed = true
	return output, nil
}
