package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	_ "github.com/lib/pq"
)

func TestBadConfirm(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}
	connStr := Conf.Database.ConnectionString
	var err error

	DB, err = sql.Open("postgres", connStr)
	defer DB.Close()
	if err != nil {
		log.Fatal(err)
		return
	}

	// enter test data in the DB
	stmt, err := DB.Prepare(`INSERT INTO didstore (id,
                          root,
                          did,
                          signing_pubkey,
                          encrypting_pubkey,
                          secret_cypher,
                          secret_nonce,
                          secret_master,
                          challenge,
                          status,
                          superseded_by,
                          created) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = stmt.Exec("did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds",
		"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds",
		`{"did":{"@context":"https://w3id.org/did/v1","created":"2018-11-16T00:58:15.687Z","id":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","publicKey":[{"id":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds#signing","owner":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","publicKeyBase64":"wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","type":"ed25519"},{"id":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds#encrypting","owner":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","publicKeyBase64":"8FYOAkydAwZ7_klEb829AIJYbWWCxT7QSTyOseRk5FA","type":"curve25519"}]}}`,
		"wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds",
		"8FYOAkydAwZ7_klEb829AIJYbWWCxT7QSTyOseRk5FA",
		"AAAAAAAAAAAAAAAAAAAAAKiFJD_pPZ5UxtVB2UpD4bzUJLTmqZv_E1xnRROoZXnl4ByT0sNvJzIs63BwfQuDzQKrcgh7oTCtwIoaqZrAda-C-FPT1g4pMCcDemZNUYXP",
		"MIhVAMplzT4kbvTWEBpEkrlR8U3K2JfI",
		"MrtvpqD0gyowr4QsRMDFrIl8ImTMckKFLf4maANnIV8",
		"93106678abb5e49c7c4f997a832e387d1ec2dc258c5301bc3f9b40d431b093bb",
		"init",
		"",
		"2018-11-16 00:58:15.707951+00:00")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	// borked the JWT HMAC
	input := `{"challengeResponse":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImRpZDpqbGluYzp3ek1nVldHTG1NZkFUdVVGZXBpc213OW1ZdEl0azRLcC02cnh2UkFpUmRzIiwic2lnbmF0dXJlIjoiQ3FOUFJJdno1cmJxN1pxelhDM19Pek1STGo5bUxZTklwelBXV3I1UTVsODNQbWFERkVUVE1NOFc2ZGdicllNcUdwNWpSeGRaMkFtSEsyakctaDRkQmciLCJpYXQiOjE1NDIzMzIyOTR9.mHAvoU40n0bnRum6pUj5SSkg78fex0jJCfmVNoXmB5Z"}`
	inputReader := strings.NewReader(input)

	didID := fmt.Sprintf("%s", `did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds`)

	req, err := http.NewRequest("POST", "/confirm", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerConfirm)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	expected := fmt.Sprintf(`{"success":"false", "error":"JWT-signature is invalid"}`)
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: want %s got %s", expected, rr.Body.String())
	}

	// check that the DB record is not marked verified
	var status string
	expected = "init"
	row := DB.QueryRow(fmt.Sprintf(`select status FROM didstore WHERE id = '%s'`, didID))
	err = row.Scan(&status)
	if status != expected {
		t.Errorf("database returned unexpected value: got %v want %v with error %v", status, expected, err)
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore WHERE id = $1")
	stmt.Exec(fmt.Sprintf("%s", didID))

}

func TestGoodConfirm(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}
	connStr := Conf.Database.ConnectionString
	var err error

	DB, err = sql.Open("postgres", connStr)
	defer DB.Close()
	if err != nil {
		log.Fatal(err)
		return
	}

	// enter test data in the DB
	stmt, err := DB.Prepare(`INSERT INTO didstore (id,
	                        root,
	                        did,
	                        signing_pubkey,
	                        encrypting_pubkey,
	                        secret_cypher,
	                        secret_nonce,
	                        secret_master,
	                        challenge,
	                        status,
	                        superseded_by,
	                        created) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = stmt.Exec("did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds",
		"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds",
		`{"did":{"@context":"https://w3id.org/did/v1","created":"2018-11-16T00:58:15.687Z","id":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","publicKey":[{"id":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds#signing","owner":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","publicKeyBase64":"wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","type":"ed25519"},{"id":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds#encrypting","owner":"did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds","publicKeyBase64":"8FYOAkydAwZ7_klEb829AIJYbWWCxT7QSTyOseRk5FA","type":"curve25519"}]}}`,
		"wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds",
		"8FYOAkydAwZ7_klEb829AIJYbWWCxT7QSTyOseRk5FA",
		"AAAAAAAAAAAAAAAAAAAAAKiFJD_pPZ5UxtVB2UpD4bzUJLTmqZv_E1xnRROoZXnl4ByT0sNvJzIs63BwfQuDzQKrcgh7oTCtwIoaqZrAda-C-FPT1g4pMCcDemZNUYXP",
		"MIhVAMplzT4kbvTWEBpEkrlR8U3K2JfI",
		"MrtvpqD0gyowr4QsRMDFrIl8ImTMckKFLf4maANnIV8",
		"93106678abb5e49c7c4f997a832e387d1ec2dc258c5301bc3f9b40d431b093bb",
		"init",
		"",
		"2018-11-16 00:58:15.707951+00:00")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	input := `{"challengeResponse":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImRpZDpqbGluYzp3ek1nVldHTG1NZkFUdVVGZXBpc213OW1ZdEl0azRLcC02cnh2UkFpUmRzIiwic2lnbmF0dXJlIjoiQ3FOUFJJdno1cmJxN1pxelhDM19Pek1STGo5bUxZTklwelBXV3I1UTVsODNQbWFERkVUVE1NOFc2ZGdicllNcUdwNWpSeGRaMkFtSEsyakctaDRkQmciLCJpYXQiOjE1NDIzMzIyOTR9.mHAvoU40n0bnRum6pUj5SSkg78fex0jJCfmVNoXmB5I"}`
	inputReader := strings.NewReader(input)

	didID := fmt.Sprintf("%s", `did:jlinc:wzMgVWGLmMfATuUFepismw9mYtItk4Kp-6rxvRAiRds`)

	req, err := http.NewRequest("POST", "/confirm", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerConfirm)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	expected := fmt.Sprintf(`{"success":"true", "id":%q}`, didID)
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: want %s got %s", expected, rr.Body.String())
	}

	// check that the DB record is now marked verified
	var status string
	expected = "verified"
	row := DB.QueryRow(fmt.Sprintf(`select status FROM didstore WHERE id = '%s'`, didID))
	err = row.Scan(&status)
	if status != expected {
		t.Errorf("database returned unexpected value: got %v want %v with error %v", status, expected, err)
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore WHERE id = $1")
	stmt.Exec(fmt.Sprintf("%s", didID))
}
