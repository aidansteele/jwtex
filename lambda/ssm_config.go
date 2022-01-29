package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"regexp"
	"strings"
)

type parameterStoreValue struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
}

func verifiersFromParameterStore(ctx context.Context, api ssmiface.SSMAPI, prefix string) (map[string]*oidc.IDTokenVerifier, error) {
	prefix = strings.TrimSuffix(prefix, "/")
	issuersPrefix := prefix + "/issuers/"
	issuerNameRegexp := regexp.MustCompile(issuersPrefix + `[^/]+$`)

	verifiers := map[string]*oidc.IDTokenVerifier{}

	err := api.GetParametersByPathPagesWithContext(ctx, &ssm.GetParametersByPathInput{Path: &prefix, Recursive: aws.Bool(true)}, func(page *ssm.GetParametersByPathOutput, lastPage bool) bool {
		for _, parameter := range page.Parameters {
			name := *parameter.Name
			if !issuerNameRegexp.MatchString(name) {
				continue
			}

			psv := parameterStoreValue{}
			err := json.Unmarshal([]byte(*parameter.Value), &psv)
			if err != nil {
				fmt.Printf("%+v\n", err)
				panic(err)
			}

			provider, err := oidc.NewProvider(ctx, psv.Issuer)
			if err != nil {
				fmt.Printf("%+v\n", err)
				panic(err)
			}

			verifier := provider.Verifier(&oidc.Config{
				ClientID:          psv.Audience,
				SkipClientIDCheck: psv.Audience == "",
			})

			issuerId := strings.TrimPrefix(name, issuersPrefix)
			verifiers[issuerId] = verifier
			fmt.Printf("issuerId=%s url=%s aud=%s\n", issuerId, psv.Issuer, psv.Audience)
		}

		return !lastPage
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return verifiers, nil
}
