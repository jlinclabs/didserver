package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	multierror "github.com/hashicorp/go-multierror"
	_ "github.com/lib/pq"
)

func agentRegister(w http.ResponseWriter, r *http.Request) {
	type AgentRegistration struct {
		AgentKey     string `json:"agentkey"`
		Registration string `json:"registration"`
	}
	var agentRegistration AgentRegistration
	if err := json.NewDecoder(r.Body).Decode(&agentRegistration); err != nil {
		http.Error(w, "Not valid JSON", 422)
		return
	}

	type regSecret struct {
		Cyphertext string `json:"cyphertext"`
		Nonce      string `json:"nonce"`
	}

	type ConfirmClaims struct {
		DID       string `json:"did"`
		Signature string `json:"signature"`
		Secret    regSecret
		jwt.StandardClaims
	}

	// parse the JWT
	token, err := jwt.ParseWithClaims(agentRegistration.Registration, &ConfirmClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		hmacSecret, err := apiAuthSecret(agentRegistration.AgentKey)
		if err != nil {
			return nil, err
		}
		return hmacSecret, nil
	})

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success":"false", "error":"JWT-%s"}`, err)
		return
	}

	// check that the JWT is valid and save local claims var into claimsData
	var claimsData *ConfirmClaims
	if claims, ok := token.Claims.(*ConfirmClaims); ok && token.Valid {
		claimsData = claims
	} else {
		// if JWT is not valid
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success":"false", "error":"Registration JWT invalid"}`)
		return
	}

	// enter data into a registration struct
	var registration Registration
	var rawDID = claimsData.DID
	json.Unmarshal([]byte(claimsData.DID), &registration.DID)
	registration.Secret.Cyphertext = claimsData.Secret.Cyphertext
	registration.Secret.Nonce = claimsData.Secret.Nonce
	registration.Signature = claimsData.Signature
	registration.Raw = rawDID
	registration.Root = registration.DID.ID
	registration.Status = "verified"
	registration.AgentID = agentRegistration.AgentKey

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

	// record the DID
	if err = recordDID(&registration); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success":false,"error":%q}`, err.Error())
		return
	}

	// record the chainlink
	addChainlink(registration.DID.ID, registration.Raw)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"success":"true", "id":%q}`, registration.DID.ID)

}
