package jwtex

const ClaimsMapperVersion = "1.0"

type ClaimsMapperInput struct {
	Version  string                 `json:"version"`
	IssuerId string                 `json:"issuerId"`
	Claims   map[string]interface{} `json:"claims"`
}

type ClaimsMapperOutput struct {
	Allow  bool                   `json:"allow"`
	Claims map[string]interface{} `json:"claims"`
}
