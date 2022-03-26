package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ed25519"
)

func confirmSupersede(w http.ResponseWriter, r *http.Request) {
	type ChallengeResponse struct {
		TokenString string `json:"challengeResponse"`
	}
	var challengeResponse ChallengeResponse
	if err := json.NewDecoder(r.Body).Decode(&challengeResponse); err != nil {
		http.Error(w, "Not valid JSON", 422)
		return
	}

	type ConfirmClaims struct {
		ID        string `json:"id"`
		Signature string `json:"signature"`
		jwt.StandardClaims
	}

	// parse the JWT
	token, err := jwt.ParseWithClaims(challengeResponse.TokenString, &ConfirmClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		hmacSecret, err := getRootJwtSecret(token.Claims.(*ConfirmClaims).ID)
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

	var (
		challenge     string
		signingPubkey string
		supersedes    string
	)

	// check that the JWT is valid
	if claims, ok := token.Claims.(*ConfirmClaims); ok && token.Valid {
		// then check that the signature is correct
		DB.QueryRow("SELECT challenge, signing_pubkey, supersedes from didstore where id = $1", claims.ID).Scan(&challenge, &signingPubkey, &supersedes)

		signedHashed := getHash(challenge)
		sig := b64Decode(claims.Signature)
		if sigVerified := ed25519.Verify(b64Decode(signingPubkey), signedHashed, sig); !sigVerified {
			// if signature doesn't verify
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"success":"false", "error":"signature does not verify"}`)
			return
		}
	} else {
		// if JWT is not valid
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success":"false", "error":"JWT invalid"}`)
		return
	}

	// everything checks, update the superseded record
	supersederID := token.Claims.(*ConfirmClaims).ID
	stmt, err := DB.Prepare(`UPDATE didstore SET superseded_by = $1, superseded_at = NOW(), status = 'superseded', modified = NOW() WHERE id = $2`)
	if err != nil {
		fmt.Printf("Errp: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-p"`)
		return
	}

	defer stmt.Close()

	_, err = stmt.Exec(supersederID, supersedes)
	if err != nil {
		fmt.Printf("Erre: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-e"`)
		return
	}

	// then set superseder status to verifed
	stmt, err = DB.Prepare(`UPDATE didstore SET status = 'verified', modified = NOW() WHERE id = $1`)
	if err != nil {
		fmt.Printf("Errs: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-s"`)
		return
	}

	defer stmt.Close()

	_, err = stmt.Exec(supersederID)
	if err != nil {
		fmt.Printf("Erra: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-a"`)
		return
	}

	// return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"success":"true", "id":%q}`, supersederID)
}
