package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// Registration contains the information necessary to register a DID
type Registration struct {
	DID           did
	Secret        secret
	Signature     string `json:"signature"`
	Challenge     string
	SigningKey    string
	EncryptingKey string
	Raw           string
	Root          string
	Supersedes    string `json:"supersedes"`
	SupersededBy  string
	Status        string
	AgentID       string
}

type secret struct {
	Cyphertext string `json:"cyphertext"`
	Nonce      string `json:"nonce"`
	MasterKey  string
}

type did struct {
	AtContext  string     `json:"@context"`
	ID         string     `json:"id"`
	CreatedAt  string     `json:"created"`
	PublicKeys publicKeys `json:"publicKey"`
}

type publicKeys []pubkey

type pubkey struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Owner           string `json:"owner"`
	PublicKeyBase64 string `json:"publicKeyBase64"`
}

// get the raw did section without emptying r.Body
func getRawDID(r *http.Request) (j string, err error) {
	type RawDid struct {
		DID interface{} `json:"did"`
	}
	var bodyBytes []byte
	// read r.Body into bodyBytes, which empties r.Body,
	// then put the content back into r.Body for the rest of the handler function
	bodyBytes, _ = ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// get the "did" section  of the request body into raw, then Marshal it back into JSON
	var raw RawDid
	json.Unmarshal(bodyBytes, &raw)
	js, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}

	return string(js), nil
}
