package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	//"github.com/hashicorp/go-multierror"

	_ "github.com/lib/pq"
)

// Registration contains the information necessary to register a DID
type Registration struct {
	DID       did
	Secret    secret
	Signature string `json:"signature"`
	Challenge string
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
	var registration Registration

	if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
		http.Error(w, "Not valid JSON", 422)
		return
	}

	// master key that the secret is encrypted with
	registration.Secret.MasterKey = Conf.Keys.Public

	if err := validateDID(&registration); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, err.Error())
		return
	}

	// instantiate the challenge
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		http.Error(w, "Error creating challenge", 500)
		return
	}
	registration.Challenge = hex.EncodeToString(challenge)

	// record the DID

	//return the challenge
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q, "challenge":%q}`, registration.DID.ID, registration.Challenge)
}
