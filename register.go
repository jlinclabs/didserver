package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	_ "github.com/lib/pq"
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
	SupersededBy  string
	SupersededAt  string
	Status        string
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

func registerDID(w http.ResponseWriter, r *http.Request) {
	j, err := getRawDID(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, err.Error())
		return
	}

	var registration Registration
	if err = json.NewDecoder(r.Body).Decode(&registration); err != nil {
		http.Error(w, "Not valid JSON", 422)
		return
	}

	// master key that the secret is encrypted with
	registration.Secret.MasterKey = Conf.Keys.Public

	// validate the registration
	if err = validateDID(&registration); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, err.Error())
		return
	}

	// add in some local values
	registration.Raw = string(j)
	registration.Root = registration.DID.ID
	registration.Status = "init"

	// instantiate the challenge
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		http.Error(w, "Error creating challenge", 500)
		return
	}
	registration.Challenge = hex.EncodeToString(challenge)

	// record the DID
	if err = recordDID(&registration); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, err.Error())
		return
	}

	//return the challenge
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q, "challenge":%q}`, registration.DID.ID, registration.Challenge)
}

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
