# jwtex

**UPDATE**: I'll keep this repo online for educational reasons, but a better approach 
is to  use Cognito's native capabilities (described in [this blog post][cognito]) 
instead of the code in this repo.

**This README is a work in progress*

`jwtex` is a serverless application that takes JSON Web Tokens (JWTs) in one format
and converts them to another format. It also acts as a basic OpenID Connect (OIDC)
identity provider to authenticate the emitted JWTs.

## Use cases

tl;dr: Create useful AWS role session tags from JWTs issued by GitHub, GitLab, etc.

GitHub Actions [can generate OIDC tokens][gha-oidc] to authenticate CI/CD jobs.
This can be used to federate into many systems, including AWS. The JWT that
GitHub generates contains a wealth of information about the job that created it,
but most of that useful information is discarded when federating into AWS. For
example, here's a GitHub JWT's claims:

```json
{
  "actor": "octocat",
  "aud": "https://github.com/octo-org",
  "base_ref": "",
  "environment": "prod",
  "event_name": "workflow_dispatch",
  "exp": 1632493867,
  "head_ref": "",
  "iat": 1632493567,
  "iss": "https://token.actions.githubusercontent.com",
  "job_workflow_ref": "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main",
  "jti": "example-id",
  "nbf": 1632492967,
  "ref": "refs/heads/main",
  "ref_type": "branch",
  "repository": "octo-org/octo-repo",
  "repository_owner": "octo-org",
  "run_attempt": "2",
  "run_id": "example-run-id",
  "run_number": "10",
  "sha": "example-sha",
  "sub": "repo:octo-org/octo-repo:environment:prod",
  "workflow": "example-workflow"
}
```

And this is what appears in CloudTrail (I've removed irrelevant fields for brevity):

```json
{
  "eventName": "AssumeRoleWithWebIdentity",
  "eventSource": "sts.amazonaws.com",
  "recipientAccountId": "0123456789012",
  "requestParameters": {
    "roleArn": "arn:aws:iam::0123456789012:role/ExampleGithubRole",
    "roleSessionName": "botocore-session-1631674835"
  },
  "responseElements": {
    "assumedRoleUser": {
      "arn": "arn:aws:sts::0123456789012:assumed-role/ExampleGithubRole/botocore-session-1631674835",
      "assumedRoleId": "AROAY99999AOBPS6VNUFM:botocore-session-1631674835"
    },
    "audience": "https://github.com/octo-org",
    "credentials": {
      "accessKeyId": "ASIAY29999OMG3MKNAG",
      "expiration": "Sep 15, 2021 4:00:36 AM",
      "sessionToken": "IQ[trimmed]lg=="
    },
    "provider": "arn:aws:iam::0123456789012:oidc-provider/token.actions.githubusercontent.com",
    "subjectFromWebIdentityToken": "repo:octo-org/octo-repo:environment:prod"
  },
  "sourceIPAddress": "104.211.45.236",
  "userAgent": "aws-cli/2.2.35 Python/3.8.8 Linux/5.8.0-1040-azure exe/x86_64.ubuntu.20 prompt/off command/sts.get-caller-identity",
  "userIdentity": {
    "identityProvider": "arn:aws:iam::0123456789012:oidc-provider/token.actions.githubusercontent.com",
    "principalId": "arn:aws:iam::0123456789012:oidc-provider/token.actions.githubusercontent.com:https://github.com/octo-org:repo:octo-org/octo-repo:environment:prod",
    "type": "WebIdentityUser",
    "userName": "repo:octo-org/octo-repo:environment:prod"
  }
}
```

The only useful information that is passed through is the `sub`. It would be really
great if we could a) record other claims of the GitHub JWT in CloudTrail and b) use
those other claims as [AWS IAM role session tags][role-tags].

# Let's make it happen

Here's how to deploy this:

* Create a new AWS account in your org solely for running `jwtex`. You should
  minimise who has access to it as it is a sensitive service.

* Deploy `jwtex` into that account:

```yaml
# jwtex.yml
Transform: AWS::Serverless-2016-10-31
Resources:
  jwtex:
    Type: AWS::Serverless::Application
    Properties:
      Location:
        ApplicationId: 'arn:aws:serverlessrepo:us-east-1:607481581596:applications/jwtex'
        SemanticVersion: '0.1.0'
    Parameters:
      Prefix: jwtex # ssm parameter prefix *without* leading slash
      CertificateArn: arn:aws:acm:us-east-1:0123456789012:certificate/ae2265dc-6397-40cf-b8e4-24f890e26d2e
      DomainName: jwtex.example.com
      HostedZoneId: Z1234YD7WANM86
      MapperFunctionArn: !GetAtt Mapper.Arn

  GithubIssuer:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /jwtex/issuers/github
      Type: String
      Value: '{"issuer": "https://token.actions.githubusercontent.com"}'

  Mapper:
    Type: AWS::Serverless::Function
    Properties:
      Architectures: [arm64]
      Runtime: nodejs14.x
      Handler: mapper.handler
      CodeUri: ./mapper.js
```

```javascript
// mapper.js
module.exports.handler = async function(input) {
    const claims = input.claims;

    if (claims.repository_owner !== "octo-org") {
        return { allow: false };
    }

    // let's extract these claims from the github jwt into
    // role session tags
    const interestingClaims = [
        "actor",
        "event_name",
        "ref",
        "repository",
        "run_attempt",
        "run_id",
        "run_number",
        "sha",
        "workflow"
    ];
    
    const tags = Object.fromEntries(interestingClaims.map(name => [
        name,
        [claims[name]]
    ]));

    claims["https://aws.amazon.com/tags"] = {
        principal_tags: tags,
        transitive_tag_keys: [],
    };

    return { allow: true, claims };
}
```

* Deploy your new OIDC IdP and roles for GitHub into each AWS account in the org:

```yaml
Resources:
  JwtexOidc:
    Type: AWS::IAM::OIDCProvider
    Properties:
      Url: https://jwtex.example.com
      ThumbprintList: ["TODO: insert thumbprint here"]
      ClientIdList: [https://github.com/octo-org]
      
  Role:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ExampleGithubRole
      ManagedPolicyArns: [arn:aws:iam::aws:policy/ReadOnlyAccess]
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Action: sts:AssumeRoleWithWebIdentity
            Principal:
              Federated: !Ref JwtexOidc
            Condition:
              StringEquals:
                aws:RequestTag/repository: octo-org/octo-repo
                aws:RequestTag/ref: refs/heads/main
          - Effect: Allow
            Action: sts:TagSession
            Principal:
              Federated: !Ref JwtexOidc
```

* Update your GHA workflows to exchange your GitHub JWT for a new JWT:

```yaml
on:
  push:

permissions:
  id-token: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS
        run: |
          export AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/awscreds
          echo AWS_WEB_IDENTITY_TOKEN_FILE=$AWS_WEB_IDENTITY_TOKEN_FILE >> $GITHUB_ENV
          
          github_jwt=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r '.value')
          url="https://jwtex.example.com/exchange?issuerId=github"
          curl -s --data-binary "$github_jwt" -o $AWS_WEB_IDENTITY_TOKEN_FILE $url
          
      - run: aws sts get-caller-identity --region us-east-1
        env:
          AWS_ROLE_ARN: arn:aws:iam::0123456789012:role/ExampleGithubRole
```

Now your role sessions have those helpful tags and your CloudTrail entries
have been enriched:

```diff
diff --git cloudtrail.json cloudtrail.json
index 649867d..2784d1a 100644
--- cloudtrail.json
+++ cloudtrail.json
@@ -3,8 +3,20 @@
   "eventSource": "sts.amazonaws.com",
   "recipientAccountId": "0123456789012",
   "requestParameters": {
+    "principalTags": {
+      "actor": "octocat",
+      "event_name": "workflow_dispatch",
+      "ref": "refs/heads/main",
+      "repository": "octo-org/octo-repo",
+      "run_attempt": "2",
+      "run_id": "example-run-id",
+      "run_number": "10",
+      "sha": "example-sha",
+      "workflow": "example-workflow"
+    },
+    "transitiveTagKeys": [],
     "roleArn": "arn:aws:iam::0123456789012:role/ExampleGithubRole",
     "roleSessionName": "botocore-session-1631674835"
   },
   "responseElements": {
     "assumedRoleUser": {
@@ -17,14 +29,15 @@
       "expiration": "Sep 15, 2021 4:00:36 AM",
       "sessionToken": "IQ[trimmed]lg=="
     },
-    "provider": "arn:aws:iam::0123456789012:oidc-provider/token.actions.githubusercontent.com",
+    "packedPolicySize": 44,
+    "provider": "arn:aws:iam::0123456789012:oidc-provider/jwtex.example.com",
     "subjectFromWebIdentityToken": "repo:octo-org/octo-repo:environment:prod"
   },
   "sourceIPAddress": "104.211.45.236",
   "userAgent": "aws-cli/2.2.35 Python/3.8.8 Linux/5.8.0-1040-azure exe/x86_64.ubuntu.20 prompt/off command/sts.get-caller-identity",
   "userIdentity": {
-    "identityProvider": "arn:aws:iam::0123456789012:oidc-provider/token.actions.githubusercontent.com",
-    "principalId": "arn:aws:iam::0123456789012:oidc-provider/token.actions.githubusercontent.com:https://github.com/octo-org:repo:octo-org/octo-repo:environment:prod",
+    "identityProvider": "arn:aws:iam::0123456789012:oidc-provider/jwtex.example.com",
+    "principalId": "arn:aws:iam::0123456789012:oidc-provider/jwtex.example.com:https://github.com/octo-org:repo:octo-org/octo-repo:environment:prod",
     "type": "WebIdentityUser",
     "userName": "repo:octo-org/octo-repo:environment:prod"
   }
--
```

[cognito]: https://awsteele.com/blog/2023/10/25/aws-role-session-tags-for-github-actions.html
[gha-oidc]: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
[role-tags]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
