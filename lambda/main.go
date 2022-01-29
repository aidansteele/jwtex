package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/aidansteele/jwtex"
	"github.com/aidansteele/jwtex/kmssigner"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	lapi "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/glassechidna/lambdahttp/pkg/gowrap"
	"os"
)

func main() {
	keyId := os.Getenv("KMS_KEY_ID")
	ssmPrefix := os.Getenv("SSM_PREFIX")
	issuerUrl := os.Getenv("ISSUER_URL")
	mapperArn := os.Getenv("MAPPER_ARN")

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *aws.NewConfig().WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint),
	})
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}
	sess.Handlers.Build.PushBack(request.MakeAddToUserAgentHandler("jwtex", "0.1"))

	signer, err := kmssigner.New(kms.New(sess), keyId)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	verifiers, err := verifiersFromParameterStore(context.Background(), ssm.New(sess), ssmPrefix)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	sum224 := sha256.Sum224([]byte(keyId))
	kid := hex.EncodeToString(sum224[:])

	srv := jwtex.NewServer(issuerUrl, kid, signer, verifiers, mapperArn, lapi.New(sess))
	lambda.StartHandler(gowrap.ApiGateway(srv))
}
