package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
)

func revoke(w http.ResponseWriter, r *http.Request) {
	type RevokeRequest struct {
		TokenString string `json:"revokeRequest"`
	}
	var revokeRequest RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&revokeRequest); err != nil {
		http.Error(w, "Not valid JSON", 422)
		return
	}

	type ConfirmClaims struct {
		ID string `json:"id"`
		jwt.StandardClaims
	}
	//parse the JWT
	token, err := jwt.ParseWithClaims(revokeRequest.TokenString, &ConfirmClaims{}, func(token *jwt.Token) (interface{}, error) {
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
		fmt.Fprintf(w, `{"success":"false", "error":"%s"}`, err)
		return
	}

	// check that the JWT is valid
	if _, ok := token.Claims.(*ConfirmClaims); !ok || !token.Valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success":"false", "error":"JWT invalid"}`)
		return
	}

	// everything checks, set DB status to revoked
	didID := token.Claims.(*ConfirmClaims).ID
	stmt, err := DB.Prepare(`UPDATE didstore SET status = 'revoked', modified = NOW() WHERE id = $1`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-p"`)
		return
	}

	defer stmt.Close()

	_, err = stmt.Exec(didID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-e"`)
		return
	}

	// return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"success":"true", "revoked":%q}`, didID)
}
