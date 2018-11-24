package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	multierror "github.com/hashicorp/go-multierror"
	_ "github.com/lib/pq"
)

func supersedeDID(w http.ResponseWriter, r *http.Request) {
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

	if errResult.ErrorOrNil() != nil {
		errResult.ErrorFormat = formatErrors
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, errResult.Error())
		return
	}

	//spew.Fdump(w, registration)

	// check that the supersedes key is an existing active DID
	stmt, err := DB.Prepare("SELECT root, status FROM didstore WHERE id = $1")
	defer stmt.Close()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-st"`)
		return
	}
	var root, status string
	err = stmt.QueryRow(registration.Supersedes).Scan(&root, &status)
	switch {
	case err == sql.ErrNoRows: //didn't find it
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"item to supersede not found"}`))
		return
	case err != nil: // query error!
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-q"`)
		return
	case status != "verified": //success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"status":"item to supersede not active"}`))
		return
	}

	// add in some local values
	registration.Raw = rawDID
	registration.Root = root
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
