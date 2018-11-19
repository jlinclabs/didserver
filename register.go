package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	multierror "github.com/hashicorp/go-multierror"
	_ "github.com/lib/pq"
)

func registerDID(w http.ResponseWriter, r *http.Request) {
	rawDID, err := getRawDID(r)
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
	var errResult *multierror.Error
	if err = validateDIDparams(&registration); err != nil {
		errResult = multierror.Append(errResult, err)
	}
	if err = getDIDkeys(&registration); err != nil {
		errResult = multierror.Append(errResult, err)
	}
	if err = validateDIDsignature(&registration); err != nil {
		errResult = multierror.Append(errResult, err)
	}
	if err = validateDIDsecret(&registration); err != nil {
		errResult = multierror.Append(errResult, err)
	}

	if errResult.ErrorOrNil() != nil {
		errResult.ErrorFormat = formatErrors
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, errResult.Error())
		return
	}

	// add in some local values
	registration.Raw = rawDID
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
